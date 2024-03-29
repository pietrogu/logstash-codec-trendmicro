# encoding: utf-8
require "logstash/util/charset"
require "logstash/codecs/base"

class LogStash::Codecs::Trendmicro < LogStash::Codecs::Base
  config_name "trendmicro"
  # Campi header per i due tipi di possibili formati
  CEF_HEADER_FIELDS = ['CEF_Version','Vendor','Product','Version','Signature_ID','Name','Severity']
  LEEF_HEADER_FIELDS = ['LEEF_Version','Vendor','Product','Version','Event_ID']
    
  # Le seguenti coppie permettono di estendere i nomi dei campi della sezione Extension dei log di TrendMicro
  MAPPINGS = {
        "act" => "Action",
	"aggregationType" => "AggregationType",
        "cat" => "Category",
        "cn1" => "HostIdentifier",
        "cn1Label" => "HostID",
        "cn2" => "FileSize",
        "cn2Label" => "FileSize",
        "cn3" => "IntrusionPreventionPacketPosition",
        "cn3Label" => "IntrusionPreventionPacketPosition",
        "cnt" => "RepeatCount",
        "cs1" => "CustomString1",#Reason/IntrusionPreventionFilterNote/SpecificSub-Rule
        "cs1Label" => "CustomString1Label",#Reason/IntrusionPreventionNote/LIDescription
        "cs2" => "TCPFlags",
        "cs2Label" => "TCPFlags",
        "cs3" => "CustomString3",#InfectedResource/PacketFragmentationInformation
        "cs3Label" => "CustomString3Label",#InfectedResource/FragmentationBits
        "cs4" => "CustomString4",#ResourceType/ICMPType
        "cs4Label" => "CustomString4Label",#ResourceType/ICMP
        "cs5" => "CustomString5",#RiskLevel/IntrusionPreventionStreamPosition
        "cs5Label" => "CustomString5Label",#RiskLevel/IntrusionPreventionStreamPosition
        "cs6" => "CustomString6",#Container/IntrusionPreventionFilterFlags
        "cs6Label" => "CustomString6Label",#Container/IntrusionPreventionFlags
        "dmac" => "DestinationMACAddress",
        "dpt" => "DestinationPort",
        "dst" => "DestinationIPAddress",
        "duser" => "UserInformation",
        "dvc" => "DeviceAddress",
        "dvchost" => "DeviceHostName",
	"dhost" => "DeviceHostname",
        "desc" => "Description",
	"dstMAC" => "DestinationMACAddress",
	"dstPort" => "DestinationPort",
        "fname" => "FileName",
        "fsize" => "FileSize",
	"filePath" => "FilePath",
	"fileHash" => "FileHas",
        "in" => "InboundBytesRead",
        "msg" => "Message",
        "mrt" => "managerReceiptTime",
	"name" => "Name",
        "out" => "OutboundBytesRead",
        "proto" => "TransportProtocol",
        "request" => "Request",
        "repeatCount" => "RepeatCount",
	"rt" => "ReceiptTime",
        "shost" => "SourceHostName",
        "smac" => "SourceMacAddress",
        "spt" => "SourcePort",
        "src" => "SourceIPAddress",
        "suid" => "SourceUserId",
        "suser" => "SourceUserName",        
        "srcMAC" => "SourceMACAddress",
	"srcPort" => "SourcePort",
	"sev" => "Severity",
	"target" => "TargetEntity",
	"targetID" => "TargetEntityID",
	"targetType" => "TargetEntityType",
	"TrendMicroDsTags" => "EventTags",
	"TrendMicroDsTenant" => "TenantName",
	"TrendMicroDsTenantId" => "TenantID",
	"TrendMicroDsMalwareTarget" => "Target",
	"TrendMicroDsMalwareTargetType" => "TargetType",
	"TrendMicroDsFileMD5" => "FileMD5",
	"TrendMicroDsFileSHA1" => "FileSHA1",
	"TrendMicroDsFileSHA256" => "FileSHA256",
	"TrendMicroDsFrameType" => "EthernetFrameType",
	"TrendMicroDsPacketData" => "PacketData",
	"TrendMicroDsDetectionConfidence" => "ThreatProbability",
	"TrendMicroDsRelevantDetectionNames" => "ProbableThreatType",
	"usrName" => "SourceUserName",
	"xff" =>"X-Forwarded-For"
  }
  
  # Regexp per individuare l'header, nella seconda si indica il separatore: '|'
  HEADER_PATTERN = /(?:\\\||\\\\|[^|])*?/
  HEADER_SCANNER = /(#{HEADER_PATTERN})#{Regexp.quote('|')}/

  # Regexp per trovare escape character nell'header (backslash o pipe)
  HEADER_ESCAPE_CAPTURE = /\\([\\|])/

  # Regexp per individuare le coppie key/value nel campo Extension
  EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\s]\w+[^\|\s\.\=\\]+)?(?==))/
  EXTENSION_VALUE_PATTERN = /(?:\S|\s++(?!#{EXTENSION_KEY_PATTERN}=))*/
  EXTENSION_KEY_VALUE_SCANNER = /(#{EXTENSION_KEY_PATTERN})=(#{EXTENSION_VALUE_PATTERN})\s*/
    
  # Regexp per trovare escape character nel campo Extension (backslash o uguale)
  EXTENSION_VALUE_ESCAPE_CAPTURE = /\\([\\=])/
  # Regexp per trovare in Extension delle key con sintassi simile a quella di un array
  EXTENSION_KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/
  

  public
  def initialize(params={})
    super(params)
    # Input deve essere codificato in UTF-8
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger
  end

  # Definiamo il parser
  def decode(data, &block)
    # Creiamo l'evento
    event = LogStash::Event.new
    # Usiamo per il log la codifica UTF-8
    @utf8_charset.convert(data)
    # Se l'encoding non ha avuto successo non andiamo avanti nel parsing, nascerebbero errori
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Nel caso ci siano caratteri a delimitare l'inizio e alla fine del log, vengono rimossi
    if data[0] == "\""
      data = data[1..-2]
    end
    
    # Il log da parsare viene inserito in una variabile dal nome unprocessed_data
    unprocessed_data = data

    # Determiniamo il formato del log da parsare (CEF o LEEF)
    if unprocessed_data.include? "CEF"
      header_fields = CEF_HEADER_FIELDS
      else 
	header_fields = LEEF_HEADER_FIELDS	
    end

    # Ciclo per parsare l'header  
    header_fields.each do |field_name|
      # Scansioniamo l'header fino al prossimo elemento di separazione ('|')
      match_data = HEADER_SCANNER.match(unprocessed_data)
      # In assenza di match il campo manca e andiamo avanti
      break if match_data.nil?
      # Il valore trovato va nella seguente variabile
      escaped_field_value = match_data[1]

      # La prossima parte di codice viene saltata se condizione verificata
      next if escaped_field_value.nil?
      # Controlliamo la presenza di escape sequence di escape e rimuoviamo
      unescaped_field_value = escaped_field_value.gsub(HEADER_ESCAPE_CAPTURE, '\1')
      # Nell'evento settiamo la coppia header-value trovata
      event.set(field_name, unescaped_field_value)
      # Conserviamo in unprocessed data tutto quello che c'è dopo il match
      unprocessed_data = match_data.post_match
    end
    # Se nel primo campo dell'header (contenente la versione di CEF o LEEF) ci sono degli spazi è presente un header syslog
    if event.get(header_fields[0]).include? ' '
      # Separa il campo cefVersion (o leefVersion) usando rpartition, che separa rispetto all'ultima occorrenza 	
      split_version = event.get(header_fields[0]).rpartition(' ')
      # La prima parte è l'header syslog
      event.set('SyslogHeader', split_version[0])
      # L'ultima parte è la versione di CEF o LEEF usata 
      # (nota: in [1] c'è l'elemento di separazione, in questo caso lo spazio) 
      event.set(header_fields[0],split_version[2])
    end
    # Leviamo "CEF:" o "LEEF:" dal campo, lasciando quindi solo il numero della versione usata
    event.set(header_fields[0], event.get(header_fields[0]).sub(/^CEF:/, '').sub(/^LEEF:/, ''))
 
    unless event.get('SyslogHeader').nil?
    # Controlla il campo Host per vedere se presenta un carattere '<'
      if event.get('SyslogHeader').include? '<'
        # Leva dal campo host il termine <.> 	
        clean_header = event.get('SyslogHeader').gsub(/\<\d+\>/,'')
	# Aggiorno l'host 
        event.set('SyslogHeader', clean_header)
      end
    end

    # Alla fine del ciclo abbiamo elaborato l'header e rimane il messaggio
    message = unprocessed_data

    if message && message.include?('=')
      # Leviamo dal messaggio eventuali caratteri di spazio alla fine e all'inizio
      message = message.strip
      # Ricaviamo le diverse coppie key/value del messaggio
      message.scan(EXTENSION_KEY_VALUE_SCANNER) do |extension_field_key, raw_extension_field_value|
        # Mappiamo per espandere le espressioni dei campi key che di norma sono abbreviate
        extension_field_key = MAPPINGS.fetch(extension_field_key, extension_field_key)
        # Regexp per evitare che key con sintassi simile a quella di un array possano creare errori
        extension_field_key = extension_field_key.sub(EXTENSION_KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')
        # Controlliamo la presenze di escape sequence e di altri simboli, poi rimuoviamo
	extension_field_value = raw_extension_field_value.gsub(EXTENSION_VALUE_ESCAPE_CAPTURE, '\1').gsub(/["]/,'').gsub("\\n",' ')
	# Nell'evento settiamo la coppia key-value trovata
        event.set(extension_field_key, extension_field_value)
      end
    end
    # Aggiungiamo il log non parsato
    event.set("RAW_MESSAGE", data)

    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
    rescue => e
      @logger.error("Failed to decode TrendMicro payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
      yield LogStash::Event.new("message" => data, "tags" => ["_TrendMicroparsefailure"])
    end
end
