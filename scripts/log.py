import json
from fpdf import FPDF
import win32evtlog
import win32evtlogutil
import win32security

def get_event_logs():
    server = None  # None means local machine
    log_type = "Security"
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []
    
    while True:
        event_records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not event_records:
            break
        
        for event in event_records:
            if event.EventID in [4624, 4625]:  # Successful and Failed logins
                event_data = {
                    "EventID": event.EventID,
                    "TimeGenerated": event.TimeGenerated.Format(),
                    "SourceName": event.SourceName,
                    "Category": event.EventCategory,
                    "User": win32security.LookupAccountSid(None, event.Sid)[0] if event.Sid else "N/A",
                    "ComputerName": event.ComputerName,
                    "Message": win32evtlogutil.SafeFormatMessage(event, log_type)
                }
                events.append(event_data)
    
    win32evtlog.CloseEventLog(hand)
    return events

def save_json(data, filename="event_logs.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"JSON saved as {filename}")

def save_pdf(data, filename="event_logs.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "Windows Security Event Logs", ln=True, align='C')
    pdf.ln(10)
    
    for event in data:
        pdf.cell(0, 10, f"Event ID: {event['EventID']}", ln=True)
        pdf.multi_cell(0, 10, f"User: {event['User']}")
        pdf.multi_cell(0, 10, f"Time: {event['TimeGenerated']}")
        pdf.multi_cell(0, 10, f"Message: {event['Message']}")
        pdf.ln(5)
    
    pdf.output(filename)
    print(f"PDF saved as {filename}")

if __name__ == "__main__":
    logs = get_event_logs()
    save_json(logs)
    save_pdf(logs)
