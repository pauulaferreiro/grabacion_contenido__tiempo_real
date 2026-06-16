import argparse
import csv
import re
import socket       #para recibir UDP
import struct
import subprocess   #para lanzar tsp
import xml.etree.ElementTree as ET 

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

TS_PACKET_SIZE = 188
SYNC_BYTE = 0x47

PAT_PID = 0x0000
SDT_PID = 0x0011
EIT_PID = 0x0012

#### MAPEO DE CONTENT_NIBBLE_LEVEL_1 -> NOMBRE CATEGORÍA (modificado)
NIBBLE1_TO_CATEGORY = {
    "0": "Undefined",
    "1": "Fiction",
    "2": "News",
    "3": "Show",
    "4": "Sports",
    "5": "Cartoons",
    "6": "Music/Dance",
    "7": "Arts/Culture",
    "8": "Social",
    "9": "Education/Science",
    "10": "Leisure hobbies",
}

def nibble1_to_category(nibble1: str) -> str:
    return NIBBLE1_TO_CATEGORY.get(str(nibble1), "Unknown")

# Limpiar el nombre que se usa para guardar el archivo
def safe_filename(name: str, max_len: int = 120) -> str:
    name = "".join(ch for ch in name if ch >= " " or ch in "\t")
    name = re.sub(r"[^\w\s\-.]", "_", name.strip() or "SIN_NOMBRE", flags=re.UNICODE)
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"_+", "_", name)
    name = name.strip("_")
    return name[:max_len] or "SIN_NOMBRE"

# Limpiar de espacios el nombre de los eventos
def normalize_event_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.replace("\n", " ").replace("\r", " ")).strip()

# Convertir intervalo de tiempo a formato hh:mm:ss
def format_timedelta_hms(td: timedelta) -> str:
    total_seconds = max(0, int(td.total_seconds()))
    return f"{total_seconds // 3600:02d}:{(total_seconds % 3600) // 60:02d}:{total_seconds % 60:02d}"

def build_output_dir_from_name(name: str) -> Path:
    cleaned = re.sub(r"[.\s]+", "", name)
    return Path.cwd() / f"fragmentos_{cleaned}"

# Convertir el Decimal Codificado en Binario a un entero
def bcd_to_int(b: int) -> int:
    return ((b >> 4) * 10) + (b & 0x0F)

def parse_dvb_duration_3bytes(data: bytes) -> timedelta:
    if len(data) != 3:
        return timedelta(0)
    hh = bcd_to_int(data[0])
    mm = bcd_to_int(data[1])
    ss = bcd_to_int(data[2])
    return timedelta(hours=hh, minutes=mm, seconds=ss)

# Convertir la fecha MJD (usada en DVB) a Año-Mes-Dia --> ECUACIONES SACADAS DE ETSI EN 300 468 (anexo C)
def mjd_to_ymd(mjd: int) -> Tuple[int, int, int]:
    y_dash = int((mjd - 15078.2) / 365.25)
    m_dash = int((mjd - 14956.1 - int(y_dash * 365.25)) / 30.6001)
    d = mjd - 14956 - int(y_dash * 365.25) - int(m_dash * 30.6001)
    k = 1 if m_dash in (14, 15) else 0
    y = y_dash + k + 1900
    m = m_dash - 1 - k * 12
    return y, m, d

# En <start_time> tenemos 5 bytes: 2 para MJD y 3 para BCD (hh:mm:ss) --> ETSI EN 300 468
def parse_dvb_start_time_5bytes(data: bytes) -> Optional[datetime]:
    if len(data) != 5:
        return None
    if all(b == 0xFF for b in data):
        return None

    mjd = (data[0] << 8) | data[1]
    y, m, d = mjd_to_ymd(mjd)
    hh = bcd_to_int(data[2])
    mm = bcd_to_int(data[3])
    ss = bcd_to_int(data[4])

    # Creamos el datetime UTC
    try:
        return datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None

def clean_dvb_text(raw: bytes) -> str:
    if not raw:
        return ""
    while raw and raw[0] < 0x20:
        raw = raw[1:]
    return raw.decode("latin-1", errors="ignore").strip()

def parse_record_ip(value: str) -> Tuple[str, int]:
    value = value.strip().replace("udp://", "")
    if ":" not in value:
        raise ValueError("Usa --record-ip en formato IP:PUERTO, por ejemplo 239.1.1.1:1234")
    host, port = value.rsplit(":", 1)
    return host.strip(), int(port.strip())

def is_valid_event_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith("EVENT_"):
        return False
    return True

@dataclass(frozen=True)
class RunningEvent:
    event_id: str
    name: str
    start_utc: datetime
    duration: timedelta
    running_status: str
    content_nibble_1: str
    content_nibble_2: str
    extended_text: str

# Para el CSV
@dataclass
class LiveEventRecord:
    service_id: int
    event: RunningEvent
    ts_path: str

@dataclass
class ServiceState:
    service_id: int
    service_name: str = ""
    pmt_pid: Optional[int] = None
    pcr_pid: Optional[int] = None
    component_pids: Set[int] = field(default_factory=set)
    output_pids: Set[int] = field(default_factory=set)

    current_event: Optional[RunningEvent] = None
    current_event_key: Optional[Tuple[str, datetime]] = None
    last_seen_eit_key: Optional[Tuple[str, datetime, str]] = None

    current_file = None
    current_fragment_path: Optional[Path] = None
    fragment_index: int = 0

    fragment_dir: Optional[Path] = None

# Ensamblar las tablas enteras PAT/PMT/EIT
class SectionAssembler:
    def __init__(self) -> None:
        self.buffer = bytearray()

    # Devuelve la lista de todas las secciones extraídas (pusi =1)
    def push_payload(self, payload: bytes, pusi: bool) -> List[bytes]:
        sections = []

        if pusi:
            if not payload:
                return sections

            # pointer_field indica cuantos bytes hay antes de empezar otra sección diferente
            pointer_field = payload[0] 
            if len(payload) < 1 + pointer_field:
                self.buffer.clear()
                return sections

            if self.buffer and pointer_field > 0:
                self.buffer.extend(payload[1:1 + pointer_field])
                sections.extend(self._extract_sections())

            self.buffer = bytearray(payload[1 + pointer_field:])
            sections.extend(self._extract_sections())
        else:
            if payload:
                self.buffer.extend(payload)
                sections.extend(self._extract_sections())

        return sections

    def _extract_sections(self) -> List[bytes]:
        out = []
        while True:
            if len(self.buffer) < 3:
                break

            table_id = self.buffer[0]
            if table_id == 0xFF:
                self.buffer.clear()
                break
            
            #section_length ocupa 12 bits
            section_length = ((self.buffer[1] & 0x0F) << 8) | self.buffer[2]
            total_len = 3 + section_length

            # No puede superar 1021 --> dado en estandar ETSI EN 30 468
            if section_length > 1021:
                self.buffer.clear()
                break

            if len(self.buffer) < total_len:
                break

            sec = bytes(self.buffer[:total_len])
            del self.buffer[:total_len]
            out.append(sec)

        return out

def merge_extended_texts(parts: List[str]) -> str:
    cleaned = [normalize_event_name(p) for p in parts if p and normalize_event_name(p)]
    return " ".join(cleaned).strip()

# Actualizar el nombre del directorio tras leer la SDT -> Utilizar el nombre del servicio
def update_service_directory_with_real_name(output_dir: Path, service: ServiceState, real_name: str) -> None:
    old_dir = output_dir / f"Recortes_Servicio_{service.service_id:04X}"
    new_dir = output_dir / f"Recortes_{safe_filename(real_name)}"

    if old_dir == new_dir:
        service.fragment_dir = new_dir 
        return

    try:
        if old_dir.exists() and not new_dir.exists():
            old_dir.rename(new_dir)
    except Exception:
        pass

    service.fragment_dir = new_dir


# =========================================================
# Parseo de paquete TS
# =========================================================

def parse_ts_packet_header(pkt: bytes) -> Optional[dict]:
    if len(pkt) != TS_PACKET_SIZE or pkt[0] != SYNC_BYTE:
        return None

    # LA COLOCACIÓN DE LOS BITS VIENE DADA EN ISO 13818-1.
    # pusi es 2º bit del byte 1. 
    pusi = bool(pkt[1] & 0x40) #0x40 = 0100 0000
    #PID son 13 bits,los 5 mas bajo del byte 1 y el resto del byte 2
    pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
    #adaption field control. bits 5 y 4 del byte 3
    afc = (pkt[3] >> 4) & 0x03 #los movemos cuatro posiciones a la derecha y nos quedamos con los dos primeros 0x03=0000 0011

    idx = 4

    if afc in (2, 3):
        if idx >= len(pkt):
            return None
        afl = pkt[idx]
        idx += 1 + afl

    if afc not in (1, 3):
        payload = b""
    else:
        if idx > len(pkt):
            return None
        payload = pkt[idx:]

    return {
        "pid": pid,
        "pusi": pusi,
        "payload": payload,
        "afc": afc,
    }

# =========================================================
# Parse PAT / PMT / SDT / EIT
# =========================================================

# Convertir cada seccion PAT en un diccionario -> {program_number}, {pmt_pid}
#### INFORMACION SACADA DE LA TABLA DEL ESTANDAR ISO 13818-1 (pag 43) ####
def parse_pat_section(section: bytes) -> Dict[int, int]:
    programs = {}
    # 8 es el numero de bytes antes del bucle de la tabla pág 43
    if len(section) < 8 or section[0] != 0x00:
        return programs
    # Nos quedamos los 12 bits del section_length
    section_length = ((section[1] & 0x0F) << 8) | section[2]
    # 3 bytes iniciales - 4 bytes del CRC (redundancia)
    end = 3 + section_length - 4
    idx = 8

    # cada programa en la PAT ocupa 4 bytes 
    while idx + 4 <= end:
        program_number = (section[idx] << 8) | section[idx + 1] #los dos primeros bytes
        pmt_pid = ((section[idx + 2] & 0x1F) << 8) | section[idx + 3]   #0x1F = 0001 1111
        if program_number != 0:
            programs[program_number] = pmt_pid
        idx += 4

    return programs

# Extraer los PIDS de los Elementary Streams de cada evento + PID de la PCR
#### INFORMACION SACADA DE LA TABLA DEL ESTANDAR ISO 13818-1 (pag 46) ####
def parse_pmt_section(section: bytes) -> Tuple[Optional[int], Set[int]]:
    #12 es el numero de bytes fijos de la cabecera
    if len(section) < 12 or section[0] != 0x02:
        return None, set()

    pcr_pid = ((section[8] & 0x1F) << 8) | section[9] #5 bits + byte completo
    program_info_length = ((section[10] & 0x0F) << 8) | section[11]

    idx = 12 + program_info_length
    section_length = ((section[1] & 0x0F) << 8) | section[2]
    end = 3 + section_length - 4

    pids = set()
    #sacamos los PIDS de los diferentes ES
    while idx + 5 <= end:
        elementary_pid = ((section[idx + 1] & 0x1F) << 8) | section[idx + 2]
        es_info_length = ((section[idx + 3] & 0x0F) << 8) | section[idx + 4]
        pids.add(elementary_pid)
        idx += 5 + es_info_length

    return pcr_pid, pids


#### INFORMACION SACADA DE LA TABLA DEL ESTANDAR ETSI EN 300 468 (pág 32) ####
def parse_sdt_section(section: bytes) -> Dict[int, str]:
    names = {}
    #11 es el numero de bytes fijos de la cabecera
    if len(section) < 11 or section[0] != 0x42:
        return names

    section_length = ((section[1] & 0x0F) << 8) | section[2]
    end = 3 + section_length - 4
    idx = 11

    # cada servicio ocupa 5 bytes
    while idx + 5 <= end:
        service_id = (section[idx] << 8) | section[idx + 1]
        descriptors_loop_length = ((section[idx + 3] & 0x0F) << 8) | section[idx + 4]
        dpos = idx + 5
        dend = dpos + descriptors_loop_length

        while dpos + 2 <= dend and dpos + 2 <= len(section):
            tag = section[dpos]
            length = section[dpos + 1]
            body = section[dpos + 2:dpos + 2 + length]

            if tag == 0x48 and len(body) >= 2:
                provider_len = body[1]
                if 2 + provider_len < len(body):
                    name_len_pos = 2 + provider_len
                    if name_len_pos < len(body):
                        service_name_len = body[name_len_pos]
                        start = name_len_pos + 1
                        end_name = start + service_name_len
                        if end_name <= len(body):
                            name = clean_dvb_text(body[start:end_name])
                            if name:
                                names[service_id] = name

            dpos += 2 + length

        idx = dend

    return names

#### INFORMACION SACADA DE LA TABLA DEL ESTANDAR ETSI EN 300 468 (pág 34) ####
def parse_eit_section(section: bytes) -> Tuple[int, List[RunningEvent]]:
    events = []

    if len(section) < 14:
        return 0, events

    # Nos quedamos unicamente con las tablas que sean del estilo present/following del TS actual
    table_id = section[0]
    if table_id != 0x4E:
        return 0, events
    
    section_length = ((section[1] & 0x0F) << 8) | section[2]
    service_id = (section[3] << 8) | section[4]

    end = 3 + section_length - 4
    idx = 14

    # cada evento ocupa 12 bytes
    while idx + 12 <= end:
        event_id = (section[idx] << 8) | section[idx + 1]
        start_utc = parse_dvb_start_time_5bytes(section[idx + 2:idx + 7])
        duration = parse_dvb_duration_3bytes(section[idx + 7:idx + 10])

        running_status_int = (section[idx + 10] >> 5) & 0x07
        descriptors_loop_length = ((section[idx + 10] & 0x0F) << 8) | section[idx + 11]

        dpos = idx + 12
        dend = dpos + descriptors_loop_length

        # valores por defecto
        event_name = f"EVENT_{event_id:04X}"
        nib1 = "0"
        nib2 = "0"
        extended_parts = []

        while dpos + 2 <= dend and dpos + 2 <= len(section):
            tag = section[dpos]
            length = section[dpos + 1]
            body = section[dpos + 2:dpos + 2 + length]

            # short_event_descriptor
            if tag == 0x4D and len(body) >= 5:
                try:
                    event_name_length = body[3]
                    name_start = 4
                    name_end = name_start + event_name_length
                    raw_name = body[name_start:name_end] if name_end <= len(body) else b""
                    decoded_name = clean_dvb_text(raw_name)
                    if decoded_name:
                        event_name = normalize_event_name(decoded_name)
                except Exception:
                    pass

            # content_descriptor
            elif tag == 0x54 and len(body) >= 2:
                content_byte = body[0]
                nib1 = str((content_byte >> 4) & 0x0F)
                nib2 = str(content_byte & 0x0F)

            # extended_event_descriptor
            elif tag == 0x4E and len(body) >= 6:
                try:
                    # Estructura ETSI EN 300 468:
                    # descriptor_number + last_descriptor_number = body[0]
                    # ISO_639_language_code = body[1:4]
                    # length_of_items = body[4]
                    items_length = body[4]

                    items_end = 5 + items_length
                    if items_end > len(body):
                        dpos += 2 + length
                        continue

                    if items_end < len(body):
                        text_length = body[items_end]
                        text_start = items_end + 1
                        text_end = text_start + text_length

                        if text_end <= len(body):
                            raw_text = body[text_start:text_end]
                            decoded_text = clean_dvb_text(raw_text)
                            if decoded_text:
                                extended_parts.append(decoded_text)
                except Exception:
                    pass

            dpos += 2 + length

        extended_text = merge_extended_texts(extended_parts)

        if start_utc is not None:
            events.append(RunningEvent(
                event_id=f"0x{event_id:04X}",
                name=event_name,
                start_utc=start_utc,
                duration=duration,
                running_status=str(running_status_int),
                content_nibble_1=nib1,
                content_nibble_2=nib2,
                extended_text=extended_text,
            ))

        idx = dend

    return service_id, events

# =========================================================
# Fragmentos
# =========================================================

def refresh_service_output_pids(service: ServiceState) -> None:
    pids = set(service.component_pids)
    if service.pmt_pid is not None:
        pids.add(service.pmt_pid)
    if service.pcr_pid is not None:
        pids.add(service.pcr_pid)

    # para poder extraer luego todo
    pids.add(PAT_PID)
    pids.add(SDT_PID)
    pids.add(EIT_PID)

    service.output_pids = pids

def close_fragment(service: ServiceState) -> None:
    if service.current_file:
        service.current_file.flush() #fuerza escritura disco
        service.current_file.close()
        service.current_file = None
        service.current_fragment_path = None

def open_new_fragment(service: ServiceState, event: RunningEvent) -> Optional[str]:
    if service.fragment_dir is None:
        return None

    service.fragment_dir.mkdir(parents=True, exist_ok=True)
    service.fragment_index += 1

    # ej: 001_Telediario_183000Z.ts
    filename = (
        f"{service.fragment_index:03d}_"
        f"{safe_filename(event.name)}_"
        f"{event.start_utc.strftime('%H%M%S')}.ts"
    )
    out_path = (service.fragment_dir / filename).resolve()
    service.current_file = out_path.open("wb")
    service.current_fragment_path = out_path
    
    return str(out_path)

def rotate_fragment_if_needed(
    service: ServiceState,
    new_event: RunningEvent,
    live_csv_events: List[LiveEventRecord],
) -> None:
    # asegurarnos que es un fragmento "running"
    if new_event.running_status != "4":
        return

    new_key = (new_event.event_id, new_event.start_utc)

    # si el fragmento es el mismo, nada
    if service.current_event_key == new_key:
        return

    #si ya teníamos uno abierto, lo cerramos
    if service.current_file:
        close_fragment(service)

    service.current_event = new_event
    service.current_event_key = new_key

    #abrimos el fichero para el evento nuevo
    ts_path = open_new_fragment(service, new_event)
    if ts_path is None:
            return
    
    live_csv_events.append(LiveEventRecord(
        service_id=service.service_id,
        event=new_event,
        ts_path=ts_path,
    ))

    print(
        f"[EVENTO] Servicio 0x{service.service_id:04X} "
        f"({service.service_name or 'SIN_NOMBRE'}) -> {new_event.name} "
        f"[{new_event.event_id}]"
    )

# =========================================================
# CSV
# =========================================================

def write_csv(
    all_events: List[LiveEventRecord],
    services: Dict[int, ServiceState],
    out_csv: Path
) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    #ordenamos por hora de inicio
    ordered = sorted(all_events, key=lambda x: x.event.start_utc)

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "SERVICIO",
            "RUTA ARCHIVO TS",
            "NOMBRE DEL EVENTO",
            "HORA DE INICIO",
            "DURACION",
            "CONTENT_NIBBLE_1",
            "CONTENT_NIBBLE_2",
            "CONTENT_CATEGORY_AUTO"
        ])

        for rec in ordered:
            service = services.get(rec.service_id)
            if service and service.service_name and not service.service_name.startswith("Servicio_"):
                service_name = service.service_name
            else:
                service_name = f"Servicio_{rec.service_id:04X}"

            writer.writerow([
                service_name,
                rec.ts_path,
                rec.event.name,
                rec.event.start_utc.strftime("%H:%M:%SZ"),
                format_timedelta_hms(rec.event.duration),
                rec.event.content_nibble_1,
                rec.event.content_nibble_2,
                nibble1_to_category(rec.event.content_nibble_1)
            ])

# =========================================================
# UDP
# =========================================================

def open_udp_socket(host: str, port: int, timeout_sec: float = 2.0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("", port))
    except OSError:
        sock.bind((host, port))

    first_octet = int(host.split(".")[0])
    if 224 <= first_octet <= 239:
        mreq = struct.pack("=4sl", socket.inet_aton(host), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    sock.settimeout(timeout_sec)
    return sock

# =========================================================
# Extracción de EIT por fragmento
# =========================================================
def filter_eit_xml_by_service(xml_input: Path, xml_output: Path, service_id: int) -> bool:
    if not xml_input.exists():
        return False

    try:
        tree = ET.parse(xml_input)
        root = tree.getroot()
    except Exception:
        return False

    service_id_hex = f"0x{service_id:04X}".lower()

    # crear un nuevo documento vacío con misma raiz
    new_root = ET.Element(root.tag, root.attrib)
    kept = 0

    for eit in root.iter():
        if eit.tag.split("}")[-1] != "EIT":
            continue

        #filtramos por service_id
        sid_attr = eit.attrib.get("service_id", "").strip().lower()
        if sid_attr in (service_id_hex, str(service_id)):
            new_root.append(eit)
            kept += 1

    if kept == 0:
        return False

    ET.ElementTree(new_root).write(xml_output, encoding="utf-8", xml_declaration=True)
    return True

def extract_eit_from_fragment(fragment_path: Path, service_id: int) -> Optional[Path]:
    #creamos completo temporal y "filtrado" (=final)
    temp_xml_path = fragment_path.with_suffix(".eit_full.xml")
    final_xml_path = fragment_path.with_suffix(".eit.xml")

    cmd = [
        "tsp",
        "-I", "file", str(fragment_path),
        "-P", "tables",
        "--pid", "0x0012",
        "--xml-output", str(temp_xml_path),
        "-O", "drop",
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        return None

    #filtramos por servicio
    ok = filter_eit_xml_by_service(temp_xml_path, final_xml_path, service_id)

    # borramos el temporal
    try:
        if temp_xml_path.exists():
            temp_xml_path.unlink()
    except Exception:
        pass

    if ok and final_xml_path.exists():
        return final_xml_path

    return None

def extract_eit_for_all_fragments(services: Dict[int, ServiceState]) -> None:
    all_fragments = []

    for service_id, service in services.items():
        if service.fragment_dir is None or not service.fragment_dir.exists():
            continue

        for frag in sorted(service.fragment_dir.glob("*.ts")):
            all_fragments.append((frag, service_id))

    if not all_fragments:
        print(" No hay fragmentos para extraer EIT.")
        return

    print(f"\nExtrayendo EIT desde {len(all_fragments)} fragmentos")
    ok = 0

    for frag, service_id in all_fragments:
        xml = extract_eit_from_fragment(frag, service_id)
        if xml is not None and xml.exists():
            ok += 1

    print(f"EIT extraída y filtrada por servicio en {ok}/{len(all_fragments)} fragmentos.")

# =========================================================
# Procesado en tiempo real
# =========================================================

def process_live_mux(
    record_ip: str,
    record_seconds: int,
    output_dir: Path,
    extract_eit_after: bool = False,
) -> int:
    # Parseamos dirección IP y creamos directorio principal
    host, port = parse_record_ip(record_ip)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Creamos las diferentes variables
    assemblers: Dict[int, SectionAssembler] = {
        PAT_PID: SectionAssembler(),
        SDT_PID: SectionAssembler(),
        EIT_PID: SectionAssembler(),
    }

    services: Dict[int, ServiceState] = {}
    pmt_pid_to_service: Dict[int, int] = {}
    all_mux_events: List[LiveEventRecord] = []

    # Calculamos hora de inicio y fin
    start_wallclock_utc = datetime.now(timezone.utc)
    deadline = start_wallclock_utc + timedelta(seconds=record_seconds)

    sock = open_udp_socket(host, port)

    print(f"Iniciando fragmentación en tiempo real desde {host}:{port}")
    print(f"Inicio UTC: {start_wallclock_utc.isoformat()}")
    print(f"Duración: {record_seconds} s")

    try:
        while datetime.now(timezone.utc) < deadline:
            try:
                datagram, _addr = sock.recvfrom(7 * TS_PACKET_SIZE)
            except socket.timeout:
                continue

            if not datagram:
                continue

            usable = len(datagram) - (len(datagram) % TS_PACKET_SIZE)

            # 1. Separamos paquetes TS
            for i in range(0, usable, TS_PACKET_SIZE):
                pkt = datagram[i:i + TS_PACKET_SIZE]
                if len(pkt) != TS_PACKET_SIZE or pkt[0] != SYNC_BYTE:
                    continue
                
                # 2. Extraemos información de la cabecera de los paquetes
                hdr = parse_ts_packet_header(pkt)
                if hdr is None:
                    continue

                pid = hdr["pid"]
                pusi = hdr["pusi"]
                payload = hdr["payload"]

                 # 3A. Reensablamos secciones de la PAT
                if pid == PAT_PID:
                    sections = assemblers[PAT_PID].push_payload(payload, pusi)
                    for sec in sections:
                        pat = parse_pat_section(sec)
                        for service_id, pmt_pid in pat.items():
                            # Para cada servicio nuevo:
                            if service_id not in services:
                                srv_dir = output_dir / f"Recortes_Servicio_{service_id:04X}"
                                # guardamos PMT 
                                services[service_id] = ServiceState(
                                    service_id=service_id,
                                    service_name=f"Servicio_{service_id:04X}",
                                    pmt_pid=pmt_pid,
                                    fragment_dir=srv_dir,
                                )
                            else:
                                services[service_id].pmt_pid = pmt_pid

                            pmt_pid_to_service[pmt_pid] = service_id
                            if pmt_pid not in assemblers:
                                assemblers[pmt_pid] = SectionAssembler()

                # 3B. Reensablamos secciones de la SDT -> Actualizamos nombre carpeta de "Recortes_X"
                elif pid == SDT_PID:
                    sections = assemblers[SDT_PID].push_payload(payload, pusi)
                    for sec in sections:
                        names = parse_sdt_section(sec)
                        for service_id, name in names.items():
                            if service_id not in services:
                                srv_dir = output_dir / f"Recortes_{safe_filename(name)}"
                                services[service_id] = ServiceState(
                                    service_id=service_id,
                                    service_name=name,
                                    fragment_dir=srv_dir ,
                                )
                            else:
                                service = services[service_id]
                                service.service_name = name
                                update_service_directory_with_real_name(output_dir, service, name)

                # 3C.Reensablamos secciones de la EIT
                elif pid == EIT_PID:
                    sections = assemblers[EIT_PID].push_payload(payload, pusi)
                    for sec in sections:
                        service_id, eit_events = parse_eit_section(sec)
                        if service_id == 0 or not eit_events:
                            continue

                        if service_id not in services:
                            srv_dir = output_dir / f"Recortes_Servicio_{service_id:04X}"
                            services[service_id] = ServiceState(
                                service_id=service_id,
                                service_name=f"Servicio_{service_id:04X}",
                                fragment_dir=srv_dir ,
                            )

                        service = services[service_id]

                        running_events = [
                            ev for ev in eit_events
                            if ev.running_status == "4" and is_valid_event_name(ev.name)
                        ]
                        if not running_events:
                            continue

                        selected = running_events[0]
                        # Clave para poder detectar repetidos
                        eit_key = (selected.event_id, selected.start_utc, selected.running_status)

                        if service.last_seen_eit_key == eit_key:
                            continue

                        service.last_seen_eit_key = eit_key
                        rotate_fragment_if_needed(service, selected, all_mux_events)

                elif pid in pmt_pid_to_service:
                    service_id = pmt_pid_to_service[pid]
                    sections = assemblers[pid].push_payload(payload, pusi)
                    for sec in sections:
                        pcr_pid, component_pids = parse_pmt_section(sec)
                        service = services[service_id]
                        service.pcr_pid = pcr_pid
                        service.component_pids = component_pids
                        refresh_service_output_pids(service)

                for service in services.values():
                    if not service.current_file:
                        continue
                    if not service.output_pids:
                        continue
                    if pid in service.output_pids:
                        service.current_file.write(pkt)

    # Cerramos Sock y los posibles fragmentos abiertos para evitar fallos
    finally:
        sock.close()
        for service in services.values():
            close_fragment(service)
    # Generamos CSV completo
    write_csv(all_mux_events, services,output_dir / "programas_divididos_MUX.csv")

    # Si existe el --extract-eit -> se extrae la EIT de cada fragmento
    if extract_eit_after:
        extract_eit_for_all_fragments(services)

    print("\nFragmentación en tiempo real terminada.")
    print(f"Resultados en: {output_dir}")
    return 0

# =========================================================
# MAIN
# =========================================================

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-ip", required=True)
    parser.add_argument("--record-seconds", required=True, type=int)
    parser.add_argument("--output-dir")
    parser.add_argument("--extract-eit-after", action="store_true")
    args = parser.parse_args()

    if args.output_dir:
        output_dir = Path(args.output_dir).expanduser().resolve()
    else:
        output_dir = build_output_dir_from_name("MUX_LIVE")

    return process_live_mux(
        record_ip=args.record_ip,
        record_seconds=args.record_seconds,
        output_dir=output_dir,
        extract_eit_after=args.extract_eit_after,
    )

if __name__ == "__main__":
    raise SystemExit(main())