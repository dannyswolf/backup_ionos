"""
================================================================================
ΛΕΠΤΟΜΕΡΗΣ ΠΕΡΙΓΡΑΦΗ ΛΕΙΤΟΥΡΓΙΑΣ, ΑΡΧΙΤΕΚΤΟΝΙΚΗΣ & ΑΠΑΙΤΗΣΕΩΝ
================================================================================

1. ΑΡΧΙΤΕΚΤΟΝΙΚΗ & ΡΟΗ ΕΡΓΑΣΙΑΣ (How it works)

    Α. Υβριδική Λειτουργία (Time-Aware Engine):
       Το script ελέγχει το ρολόι του συστήματος σε κάθε εκτέλεση:
       * Maintenance Window (23:55): Ενεργοποιεί τη διαδικασία Full Backup.
         1. Στέλνει εντολή Docker Compose Stop (ως χρήστης docker).
         2. Συλλέγει ρυθμίσεις (Apache, IPSet, Fail2Ban, Permissions).
         3. Δημιουργεί ZIP στον IONOS και το μεταφέρει στο QNAP.
         4. Επαναφέρει τις υπηρεσίες (Docker Compose Up).
       * Standard Window: Λειτουργεί αποκλειστικά για τον συγχρονισμό καμερών.

    Β. Παράλληλη Μεταφορά (Multi-threaded Workers):
       Χρησιμοποιεί την ThreadPoolExecutor για άνοιγμα πολλαπλών SSH καναλιών 
       ταυτόχρονα, εξαλείφοντας την καθυστέρηση (latency) του δικτύου.

    Γ. Μηχανισμός Ασφαλείας & Ακεραιότητας (Integrity Lock):
       Σύγκριση μεγέθους αρχείου (Bytes) μεταξύ πηγής (IONOS) και προορισμού (QNAP).
       Η εντολή διαγραφής RM εκτελείται ΜΟΝΟ αν το αρχείο έχει μεταφερθεί 100%.

    Δ. Έξυπνη Διαχείριση Χώρου (The 5-Minute Safety Rule):
       Διαγραφή αρχείων από τον IONOS μόνο αν η ηλικία τους > 300 δευτερόλεπτα,
       για αποφυγή διαγραφής αρχείων που βρίσκονται ακόμη υπό εγγραφή.

       ΣΥΝΟΨΗ ΛΟΓΙΚΗΣ ΛΗΨΗΣ ΑΠΟΦΑΣΕΩΝ:
       -------------------------------------------------------------------------
       Κατάσταση Αρχείου | Στο QNAP; | Ηλικία > 5λ; | Ενέργεια
       -------------------------------------------------------------------------
       Νέο (Πρόσφατο)    | Όχι       | Όχι          | Download & Keep on Remote
       Νέο (Ώριμο)       | Όχι       | Ναι          | Download & Delete from Remote
       Παλιό (Sync-ed)   | Ναι       | Ναι          | Delete from Remote
       Παλιό (Μη ώριμο)  | Ναι       | Όχι          | No Action (Waiting)
       -------------------------------------------------------------------------

2. ΔΙΑΧΕΙΡΙΣΗ ΕΥΑΙΣΘΗΤΩΝ ΔΕΔΟΜΕΝΩΝ (.env) & EMAIL

    * Zero-Secret Code: Φόρτωση ρυθμίσεων μέσω `python-dotenv`.
    * SMTP Alerts: Αυτόματη αποστολή email σε περίπτωση Exception.
    * Ασφάλεια: Χρήση STARTTLS και App Passwords (SMTP Port 587).

3. ΠΡΟΫΠΟΘΕΣΕΙΣ ΕΓΚΑΤΑΣΤΑΣΗΣ (Requirements)

    Στο QNAP (Client):
    - Python 3.x, Pip.
    - Libraries: `pip install paramiko python-dotenv`.
    - Αρχείο `.env` στον ίδιο φάκελο με το script.

    Στον IONOS (Server):
    - SSH Key πρόσβαση (passwordless).
    - Χρήστης μέλος του 'docker' group (για docker-compose χωρίς sudo).
    - Ρύθμιση 'Sudoers' (sudo visudo) για τις εξής εντολές:
      ονομα_χρήστη ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/zip, /usr/sbin/ipset, /usr/bin/stat, /usr/bin/journalctl, /usr/bin/rm -f /tmp/*, /usr/bin/tee /tmp/*, /bin/cp * /tmp/*


4. ΚΑΤΑΓΡΑΦΗ (Logging Strategy)

    Logs στο SYSTEM_LOG:
    - [ SYSTEM ]: Docker operations, ZIP tasks, Maintenance steps.
    - [ CAMERA ]: Worker activity, File transfers, Remote cleanups.
    - [ ERROR ]: Καταγραφή αποτυχιών και status αποστολής email.

5. ΕΠΑΝΑΦΟΡΑ (RESTORE)
    
    Δικαιώματα: Το ZIP περιέχει το files_permissions.txt. Επαναφορά με:
    * while read -r path perm owner group; do sudo chmod "$perm" "$path"; sudo chown "$owner:$group" "$path"; done < files_permissions.txt
    * IPSet: sudo ipset restore < ipset_backup.conf
================================================================================

"""

# Εισαγωγή της βιβλιοθήκης paramiko για τη σύνδεση SSH
import paramiko
# Εισαγωγή της βιβλιοθήκης os για αλληλεπίδραση με το λειτουργικό σύστημα
import os
# Εισαγωγή της βιβλιοθήκης stat για έλεγχο τύπων αρχείων και δικαιωμάτων
import stat
# Εισαγωγή της βιβλιοθήκης logging για την καταγραφή συμβάντων σε αρχεία
import logging
# Εισαγωγή της βιβλιοθήκης datetime για τη διαχείριση ημερομηνιών και ώρας
import datetime
# Εισαγωγή του ThreadPoolExecutor για την παράλληλη εκτέλεση εργασιών
from concurrent.futures import ThreadPoolExecutor

# Το smtplib είναι η ενσωματωμένη βιβλιοθήκη της Python που αναλαμβάνει 
# την επικοινωνία με έναν διακομιστή αλληλογραφίας (Mail Server) 
# χρησιμοποιώντας το πρωτόκολλο SMTP (Simple Mail Transfer Protocol).
# Σκεφτείτε το ως τον "ταχυδρόμο" που ανοίγει τη σύνδεση και παραδίδει το γράμμα.
import smtplib

# Από τη βιβλιοθήκη email.mime, εισάγουμε το MIMEText.
# Αυτό χρησιμεύει στη δημιουργία του ίδιου του μηνύματος (του "φακέλου").
# Επιτρέπει στον κώδικα να ορίσει το θέμα (Subject), τον αποστολέα (From), 
# τον παραλήπτη (To) και το σώμα του κειμένου σε σωστή μορφή 
# ώστε να το αναγνωρίζουν οι εφαρμογές email (π.χ. Outlook, Gmail).
from email.mime.text import MIMEText

# Εισαγωγή της συνάρτησης load_dotenv από τη βιβλιοθήκη python-dotenv.
# Αυτή η βιβλιοθήκη επιτρέπει στην Python να διαβάζει αρχεία κειμένου (όπως το .env) 
# και να τα μετατρέπει σε μεταβλητές περιβάλλοντος του συστήματος.
from dotenv import load_dotenv

# Εκτέλεση της συνάρτησης load_dotenv(). 
# Μόλις καλεστεί, η Python ψάχνει στον ίδιο φάκελο για ένα αρχείο με το όνομα ".env".
# Αν το βρει, διαβάζει τα ζεύγη KEY=VALUE και τα "φορτώνει" στη μνήμη, 
# έτσι ώστε η εντολή os.getenv() να μπορεί να τα ανακτήσει στη συνέχεια.
load_dotenv()

# --- ΑΝΑΓΝΩΣΗ ΡΥΘΜΙΣΕΩΝ ΑΠΟ ΤΟ .ENV ---

# Μεταβλητή ελέγχου αποσφαλμάτωσης. 
# Μετατρέπει το string 'True' από το .env σε πραγματική Boolean τιμή (True/False).
# Το .strip() αφαιρεί τυχόν κενά που μπορεί να υπάρχουν γύρω από την τιμή.
DEBUG = os.getenv('DEBUG', 'False').strip() == 'True'

# Στοιχεία σύνδεσης SSH για τον απομακρυσμένο σέρβερ IONOS
IONOS_IP = os.getenv('IONOS_IP')      # Η IP διεύθυνση του σέρβερ
IONOS_USER = os.getenv('IONOS_USER')  # Το όνομα χρήστη 
SSH_KEY_PATH = os.getenv('SSH_KEY_PATH') # Η πλήρης διαδρομή του ιδιωτικού κλειδιού SSH

# Διαδρομές αρχείων στον απομακρυσμένο σέρβερ (Remote)
REMOTE_BEE_DIR = os.getenv('REMOTE_BEE_DIR') # Ο φάκελος του project 
# Ο προσωρινός φάκελος για το ZIP. Αν δεν οριστεί στο .env, παίρνει την προεπιλογή '/tmp'
REMOTE_ZIP_TMP = os.getenv('REMOTE_ZIP_TMP', '/tmp') 
REMOTE_VIGI_DIR = os.getenv('REMOTE_VIGI_DIR') # Ο φάκελος με τις καταγραφές των καμερών VIGI

# Διαδρομές αρχείων τοπικά (QNAP)
LOCAL_BACKUP_DIR = os.getenv('LOCAL_BACKUP_DIR') # Πού θα αποθηκεύονται τα System Backups
LOCAL_VIGI_DIR = os.getenv('LOCAL_VIGI_DIR')     # Πού θα συγχρονίζονται τα αρχεία των καμερών

# Ρυθμίσεις απόδοσης και καταγραφής
# Ο αριθμός των Threads που θα δουλεύουν ταυτόχρονα για το κατέβασμα αρχείων (default: 2)
MAX_WORKERS = int(os.getenv('MAX_WORKERS', 2))
# Η διαδρομή του κεντρικού αρχείου καταγραφής (Log file)
SYSTEM_LOG = os.getenv('SYSTEM_LOG')

# --- ΡΥΘΜΙΣΕΙΣ EMAIL (SMTP Settings) ---
SMTP_SERVER = os.getenv('SMTP_SERVER') # Ο server του παρόχου (π.χ. smtp.gmail.com)
# Η θύρα επικοινωνίας. Μετατρέπεται σε ακέραιο (integer). Default η 587 (TLS)
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')     # Η διεύθυνση email από την οποία θα φεύγουν τα σφάλματα
SMTP_PASS = os.getenv('SMTP_PASS')     # Ο κωδικός εφαρμογής (App Password) για το email
EMAIL_RECEIVER = os.getenv('EMAIL_RECEIVER') # Η διεύθυνση που θα λάβει την ειδοποίηση σφάλματος

# Πληροφορίες: Ορισμός της συνάρτησης setup_logger για τη δημιουργία ενός κεντρικού μηχανισμού καταγραφής.
def setup_logger(name, log_file, level=logging.INFO):
    """
    Δημιουργεί και ρυθμίζει έναν Logger για την καταγραφή σε αρχείο.
    Προσθέτει το όνομα (name) στην αρχή κάθε γραμμής για εύκολο διαχωρισμό.
    """
    # Πληροφορίες: Δημιουργία αντικειμένου μορφοποίησης.
    # ΣΥΝΔΕΣΗ: Το '%(name)-12s' αφήνει σταθερό χώρο 12 χαρακτήρων για το όνομα, ώστε τα μηνύματα να είναι στοιχισμένα.
    formatter = logging.Formatter('%(asctime)s - %(name)-12s - %(levelname)s - %(message)s')
    
    # Πληροφορίες: Δημιουργία handler για εγγραφή στο αρχείο.
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    
    # Πληροφορίες: Λήψη του logger και καθαρισμός παλιών handlers (αν υπάρχουν) για αποφυγή διπλών εγγραφών.
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)
    
    return logger

# Πληροφορίες: Αν η μεταβλητή DEBUG είναι True, ενημέρωση στην κονσόλα.
if DEBUG:
    print(f"DEBUG: Έναρξη παραμετροποίησης Logs στο αρχείο: {SYSTEM_LOG}")

# --- ΔΗΜΙΟΥΡΓΙΑ LOGGERS ΜΕ ΔΙΑΚΡΙΤΙΚΑ ---

# Πληροφορίες: Δημιουργία του logger για το σύστημα (Backup, Docker).
# ΣΥΝΔΕΣΗ: Τα μηνύματα θα ξεκινούν με '[ SYSTEM ]' για να ξεχωρίζουν από τις κάμερες.
sys_logger = setup_logger('[ SYSTEM ]', SYSTEM_LOG)

# Πληροφορίες: Δημιουργία του logger για τις κάμερες (Sync, Transfer, Cleanup).
# ΣΥΝΔΕΣΗ: Τα μηνύματα θα ξεκινούν με '[ CAMERA ]' για να γνωρίζουμε ποια υπηρεσία κατέβασε το αρχείο.
cam_logger = setup_logger('[ CAMERA ]', SYSTEM_LOG)

# Επιβεβαίωση ενοποίησης αν το DEBUG είναι ενεργό
if DEBUG:
    print(f"DEBUG: Οι Loggers [ SYSTEM ] και [ CAMERA ] είναι έτοιμοι.")


def send_error_email(error_details):
    """
    Στέλνει ειδοποίηση μέσω email όταν προκύψει σφάλμα στο backup.
    Χρησιμοποιεί τις ρυθμίσεις SMTP που έχουν φορτωθεί από το .env.
    """
    # 1. Έλεγχος αν υπάρχουν οι απαραίτητες ρυθμίσεις
    # Αν λείπει ο χρήστης ή ο κωδικός, σταματάει η συνάρτηση για να μην "κρασάρει" το script
    if not all([SMTP_USER, SMTP_PASS, EMAIL_RECEIVER]):
        sys_logger.error("Το email δεν εστάλη: Λείπουν οι ρυθμίσεις SMTP από το .env")
        return

    # 2. Προετοιμασία του περιεχομένου του email
    subject = f"⚠️ ALERT: Backup Failure - {IONOS_IP}"
    
    # Δημιουργούμε το σώμα του μηνύματος με την ώρα και την περιγραφή του σφάλματος
    body = (
        f"Η διαδικασία αντιγράφων ασφαλείας απέτυχε.\n"
        f"----------------------------------------\n"
        f"ΣΦΑΛΜΑ: {error_details}\n"
        f"ΗΜΕΡΟΜΗΝΙΑ/ΩΡΑ: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"ΣΕΡΒΕΡ: {IONOS_IP}\n"
        f"----------------------------------------\n"
        f"Παρακαλώ ελέγξτε το αρχείο logs: {SYSTEM_LOG}"
    )

    # 3. Δημιουργία του αντικειμένου MIMEText (μορφή email)
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_RECEIVER

    # 4. Διαδικασία αποστολής
    try:
        # Σύνδεση στον SMTP Server (π.χ. Gmail) χρησιμοποιώντας τη θύρα (π.χ. 587)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Ενεργοποίηση κρυπτογράφησης TLS για ασφάλεια
            
            # Είσοδος στο λογαριασμό με το App Password
            server.login(SMTP_USER, SMTP_PASS)
            
            # Αποστολή του μηνύματος
            server.send_message(msg)
            
            sys_logger.info("Το email ειδοποίησης σφάλματος στάλθηκε επιτυχώς.")
            
    except Exception as e:
        # Καταγραφή αποτυχίας αποστολής του ίδιου του email στα logs
        sys_logger.error(f"Αποτυχία κατά την αποστολή του email ειδοποίησης: {e}")

# Ορισμός συνάρτησης για την εκτέλεση εντολών SSH στον IONOS
def run_remote_cmd(ssh, command):
    """
    Εκτελεί μια εντολή στο τερματικό του IONOS και επιστρέφει το αποτέλεσμα.
    """
    # Έλεγχος αν η λειτουργία αποσφαλμάτωσης είναι ενεργή
    if DEBUG:
        # Εκτύπωση της συνάρτησης
        print(f"[DEBUG] Τοποθεσία: run_remote_cmd")
        # Εκτύπωση της εντολής
        print(f"[DEBUG] Ενέργεια: {command}")
    sys_logger.info(f"[DEBUG] Τοποθεσία: run_remote_cmd")
    sys_logger.info(f"[DEBUG] Ενέργεια: {command}")
    # Αποστολή και εκτέλεση της εντολής
    stdin, stdout, stderr = ssh.exec_command(command)
    # Λήψη του κωδικού εξόδου
    exit_status = stdout.channel.recv_exit_status()
    # Επιστροφή εξόδου και σφαλμάτων
    return stdout.read().decode(), stderr.read().decode()


# Ορισμός της κύριας συνάρτησης για το πλήρες backup του συστήματος
def perform_full_system_backup(ssh, sftp):
    """
    Εκτελεί τη ροή εργασιών του Full System Backup με αναλυτική καταγραφή (Logging).
    """
    # Ημερομηνία και Ονόματα αρχείων
    now = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M")
    zip_name = f"full_server_backup_{now}.zip"
    remote_zip_path = f"{REMOTE_ZIP_TMP}/{zip_name}"
    local_zip_path = f"{LOCAL_BACKUP_DIR}/{zip_name}"
    perm_file = f"{REMOTE_ZIP_TMP}/files_permissions.txt"
    # Αρχείο Journal (Αντικαθιστά το auth.log που δεν υπάρχει ως αρχείο)
    journal_file = "/tmp/full_system_journal.txt"

    sys_logger.info(f"--- ΕΝΑΡΞΗ ΠΛΗΡΟΥΣ BACKUP: {zip_name} ---")
    sys_logger.info(f"Τοπική διαδρομή αποθήκευσης: {local_zip_path}")
    
    try:
        # Βήμα 1: Docker
        sys_logger.info("Βήμα 1: Προετοιμασία Docker...")
        sys_logger.info(f"Εντολή: Μετάβαση στο {REMOTE_BEE_DIR} και διακοπή containers.")
        run_remote_cmd(ssh, f"cd {REMOTE_BEE_DIR} && docker-compose stop")
        sys_logger.info("Τα Docker containers σταμάτησαν επιτυχώς.")

        # Βήμα 2: Προετοιμασία Αρχείων Logs & Configs
        sys_logger.info("Βήμα 2: Συλλογή αρχείων συστήματος και Logs...")
        
        # Permissions
        sys_logger.info(f"Δημιουργία αρχείου δικαιωμάτων: {perm_file}")
        restore_instr = (
            "# --- ΟΔΗΓΙΕΣ ΕΠΑΝΑΦΟΡΑΣ (Permissions & Owners) ---\\n"
            "# Αν χρειαστεί restore, τρέξε την παρακάτω εντολή:\\n"
            "# while read -r path perm owner group; do sudo chmod \\\"$perm\\\" \\\"$path\\\"; sudo chown \\\"$owner:$group\\\" \\\"$path\\\"; done < files_permissions.txt\\n"
        )
        
        # [DEBUG]: Εκτύπωση αν το DEBUG είναι True
        if DEBUG: print(f"[DEBUG] Τοποθεσία: perform_full_system_backup | Ενέργεια: Εγγραφή οδηγιών στο {perm_file}")
        
        # Εγγραφή οδηγιών (χρήση '>' για καθαρισμό αρχείου)
        run_remote_cmd(ssh, f"echo -e '{restore_instr}' > {perm_file}")
        
        # IPSet
        sys_logger.info("Εξαγωγή τρέχουσας λίστας IPSet (Greek Drop) στο /tmp/ipset_backup.conf")
        run_remote_cmd(ssh, "sudo /bin/bash -c '/usr/sbin/ipset save > /tmp/ipset_backup.conf'")

        # Journal
        sys_logger.info(f"Εξαγωγή System Journal (τελευταίες 24 ώρες) στο {journal_file}")
        run_remote_cmd(ssh, f"sudo /usr/bin/journalctl --since '24 hours ago' | sudo /usr/bin/tee {journal_file} > /dev/null")

        # Λίστα φακέλων για έλεγχο (ΕΠΑΝΑΦΟΡΑ ΟΛΩΝ ΤΩΝ ΣΤΟΙΧΕΙΩΝ ΣΟΥ)
        dirs_to_check = [
            REMOTE_BEE_DIR,          # 1 Project & Docker Files
            "/etc/apache2",          # 2 Web Server Configs
            "/etc/ssh/sshd_config",  # 3 SSH Access Security
            "/etc/fail2ban",         # 4 Brute Force Protection
            "/etc/ufw",              # 5 Firewall Basic Rules
            "/etc/iptables",         # 6 Advanced Firewall Rules (v4)
            "/var/log/apache2",      # 7 Web Logs Directory
            "/var/lib/fail2ban",     # 8 Fail2Ban Database Directory
            "/etc/ipset.conf"        # 9 Greek IP List File
        ]
        
        sys_logger.info("Καταγραφή permissions για όλους τους κρίσιμους φακέλους.")
        # Ένωση λίστας και εκτέλεση find
        check_space = " ".join(dirs_to_check)
        
        # [ΠΛΗΡΟΦΟΡΙΕΣ]: Χρησιμοποιούμε {{ }} για να μην μπερδεύεται η Python με το f-string.
        # [ΣΥΝΔΕΣΗ]: Το find χρειάζεται τα άγκιστρα για να ξέρει πού να βάλει τα ονόματα των αρχείων.
        cmd_find = f"sudo -n find {check_space} -maxdepth 2 -exec stat --format='%n %a %U %G' {{}} + >> {perm_file}"
        
        run_remote_cmd(ssh, cmd_find)

        # Αντίγραφο sudoers
        sys_logger.info("Δημιουργία αντιγράφου του αρχείου /etc/sudoers.")
        run_remote_cmd(ssh, "sudo cp /etc/sudoers /tmp/sudoers_backup.txt")
        
        # Λίστα αρχείων προς ZIP 
        files_list = [
            REMOTE_BEE_DIR,                             # 1 Φάκελος project και Docker
            "/etc/apache2/",                            # 2 Ρυθμίσεις Apache
            "/etc/ssh/sshd_config",                     # 3 Ρυθμίσεις SSH
            "/etc/fail2ban/",                           # 4 Προστασία Fail2Ban
            "/etc/ufw/",                                # 5 Ρυθμίσεις Firewall
            "/etc/iptables/rules.v4",                   # 6 Κανόνες Iptables (Greek Drop)
            "/etc/logrotate.d/",                        # 7 Ρυθμίσεις logrotate
            "/etc/ipset.conf",                          # 8 Η λίστα με τις 461 ελληνικές IP
            "/etc/docker/daemon.json",                  # 9 Ρυθμίσεις Docker
            "/etc/sysctl.conf",                         # 10 Ρυθμίσεις Kernel
            "/etc/fstab",                               # 11 Mount points δίσκων
            "/var/log/apache2/",                        # 12 Logs Apache
            "/var/lib/fail2ban/fail2ban.sqlite3",       # 13 Η βάση δεδομένων με τα bans
            "/var/log/fail2ban.log",                    # 14 Ενεργό fail2ban log
            journal_file,                               # 15 ΟΛΑ τα logs (Journal) 24ώρου
            "/tmp/sudoers_backup.txt",                  # 16 Αντίγραφο sudoers
            "/tmp/ipset_backup.conf",                   # 17 Greek IP List File (τρέχον)
            perm_file                                   # 18 Αρχείο permissions
        ]
        all_files = " ".join(files_list)

        # Βήμα 3: ZIP
        # Πληροφορίες: Καταγραφή έναρξης του Βήματος 3 στο Log
        sys_logger.info("Βήμα 3: Συμπίεση αρχείων σε ZIP ")
        
        # Πληροφορίες: Δημιουργία της εντολής ZIP με χρήση του nice -n 19 για ελάχιστη χρήση CPU
        # ΣΥΝΔΕΣΗ: Χρησιμοποιούμε 'nice -n 19' για να μην κολλήσει ο server και '-1' για την ταχύτερη (αλλά λιγότερο συμπιεσμένη) μέθοδο.
        # Δεν το έβαλα γιατί πρεπει να βαλω το /usr/bin/nice στο visudo
        # zip_cmd = (
        #             f"sudo /usr/bin/nice -n 19 /usr/bin/zip -1 -r {remote_zip_path} {all_files} "
        #             f"-x '/var/log/apache2/*.gz' '/var/log/apache2/*.1' '/var/log/fail2ban.log.*'"
        #             )
        
        
        zip_cmd = (
            f"sudo /usr/bin/zip -1 -r {remote_zip_path} {all_files} "
            f"-x '/var/log/apache2/*.gz' '/var/log/apache2/*.1' '/var/log/fail2ban.log.*'"
        )
        
        # Πληροφορίες: Αν η μεταβλητή DEBUG είναι True, εκτύπωση της εντολής που πρόκειται να εκτελεστεί
        if DEBUG: 
            print(f"DEBUG: Προετοιμασία εντολής ZIP: {zip_cmd}")
            
        sys_logger.info(f"Εκτέλεση ZIP: {remote_zip_path}")
        # Πληροφορίες: Εκτέλεση της εντολής στον απομακρυσμένο server μέσω SSH
        # ΣΥΝΔΕΣΗ: Συνδέουμε την εντολή που φτιάξαμε παραπάνω με τη συνάρτηση run_remote_cmd για την εκτέλεση.
        run_remote_cmd(ssh, zip_cmd)
        
        # Πληροφορίες: Αν η μεταβλητή DEBUG είναι True, επιβεβαίωση ότι η ροή πέρασε το σημείο του ZIP
        if DEBUG: 
            print("DEBUG: Η εντολή run_remote_cmd ολοκληρώθηκε για το αρχείο ZIP.")
        sys_logger.info("Η συμπίεση ολοκληρώθηκε.")

        # Βήμα 4: SFTP
        sys_logger.info("Βήμα 4: Μεταφορά αρχείου στο QNAP...")
        if DEBUG: 
            print("DEBUG: Βήμα 4: Μεταφορά αρχείου στο QNAP....")
        sftp.get(remote_zip_path, local_zip_path)
        sys_logger.info(f"Το αρχείο μεταφέρθηκε επιτυχώς: {zip_name}")
        if DEBUG: 
            print(f"DEBUG: ο αρχείο μεταφέρθηκε επιτυχώς: {zip_name}")

    except Exception as e:
        sys_logger.error(f"!!! ΣΦΑΛΜΑ ΚΑΤΑ ΤΗ ΔΙΑΡΚΕΙΑ ΤΟΥ BACKUP: {e}")
        if DEBUG: 
            print(f"DEBUG: !!! ΣΦΑΛΜΑ ΚΑΤΑ ΤΗ ΔΙΑΡΚΕΙΑ ΤΟΥ BACKUP: {e}")
    
    finally:
        # Βήμα 5: Καθαρισμός & Restart
        sys_logger.info("Βήμα 5: Ολοκλήρωση και καθαρισμός συστήματος...")
        
        sys_logger.info("Επανεκκίνηση Docker containers (docker-compose up -d).")
        run_remote_cmd(ssh, f"cd {REMOTE_BEE_DIR} && docker-compose up -d")
        
        sys_logger.info("Διαγραφή προσωρινών αρχείων από τον σέρβερ (ZIP, logs, configs).")
        # [ΠΛΗΡΟΦΟΡΙΕΣ]: Χρησιμοποιούμε sudo rm για να σβήσουμε τα αρχεία που ανήκουν στον root.
        # [ΠΛΗΡΟΦΟΡΙΕΣ]: Καθαρίζουμε τα προσωρινά αρχεία χρησιμοποιώντας το πλήρες μονοπάτι.
        # [ΠΛΗΡΟΦΟΡΙΕΣ]: Σβήνουμε τα αρχεία ένα-ένα με το πλήρες όνομά τους.
        # [ΣΥΝΔΕΣΗ]: Έτσι δεν χρειαζόμαστε αστεράκια και άρα δεν χρειαζόμαστε το sh ή το bash στο visudo.
        files_to_clean = [
                            remote_zip_path, 
                            "/tmp/sudoers_backup.txt", 
                            journal_file, 
                            perm_file, 
                            "/tmp/ipset_backup.conf"
                        ]
        
        
        # [ΠΛΗΡΟΦΟΡΙΕΣ]: Φτιάχνουμε μια λίστα με όλα τα αρχεία χωρισμένα με κενό.
        # [ΣΥΝΔΕΣΗ]: Έτσι στέλνουμε ΜΙΑ εντολή στο SSH και ο σέρβερ τα σβήνει όλα ταυτόχρονα.
        all_files_str = " ".join(files_to_clean)
        cleanup_cmd = f"sudo -n /usr/bin/rm -f {all_files_str}"
        
        if DEBUG:
            print(f"DEBUG: Εκτέλεση τελικού καθαρισμού: {cleanup_cmd}")
        
        sys_logger.info(f"Τοποθεσία: cleanup | Ενέργεια: Διαγραφή του {all_files_str} | Εκτέλεση: {cleanup_cmd}")
        stdout, stderr = run_remote_cmd(ssh, cleanup_cmd)
        
        if not stderr:
            sys_logger.info("Ο φάκελος /tmp καθαρίστηκε επιτυχώς από όλα τα προσωρινά αρχεία.")
        else:
            sys_logger.error(f"Σφάλμα κατά τον καθαρισμό: {stderr}")
            
    
        sys_logger.info("--- ΤΕΛΟΣ ΔΙΑΔΙΚΑΣΙΑΣ BACKUP ---")


# Πληροφορίες: Κεντρική συνάρτηση ελέγχου ηλικίας και διαγραφής από τον IONOS.
# ΣΥΝΔΕΣΗ: Αυτή η συνάρτηση καλείται δύο φορές: 
#         1. Από τον Manager (για αρχεία που ήδη έχουμε).
#         2. Από τον Worker (για αρχεία που μόλις κατεβάσαμε)
def check_and_remove_remote(sftp, remote_path, age_seconds, context_msg):
    """
    ΠΛΗΡΟΦΟΡΙΕΣ: Κεντρική συνάρτηση ελέγχου ηλικίας και διαγραφής από τον IONOS.
    ΣΥΝΔΕΣΗ: Ενοποιεί τη λογική για να μην γράφουμε τον ίδιο κώδικα (if/remove) δύο φορές.
    """
    fname = os.path.basename(remote_path)
    limit = 300  # Το όριο των 5 λεπτών (σε δευτερόλεπτα)

    # Έλεγχος αν το αρχείο ξεπερνά το χρονικό όριο
    if age_seconds > limit:
        try:
            # Εκτέλεση της διαγραφής
            sftp.remove(remote_path)
            
            # Καταγραφή στο Log (CameraSync logger)
            cam_logger.info(f"ΚΑΘΑΡΙΣΜΟΣ ({context_msg}): Διαγράφηκε το {fname} (Ηλικία: {int(age_seconds)}s > {limit}s).")
            
            # Αναλυτική εκτύπωση αν το DEBUG είναι ενεργό
            if DEBUG: 
                print(f"DEBUG [Cleanup]: Επιτυχής διαγραφή: {remote_path} | Αιτία: {context_msg}")
            
            return True
        except Exception as e:
            # Καταγραφή αποτυχίας
            cam_logger.error(f"ΑΠΟΤΥΧΙΑ ΔΙΑΓΡΑΦΗΣ {fname} ({context_msg}): {str(e)}")
            if DEBUG: 
                print(f"DEBUG [Error]: Αποτυχία στο sftp.remove για το {fname}: {e}")
            return False
    else:
        # Αν το αρχείο είναι "φρέσκο", το διατηρούμε στον IONOS
        cam_logger.info(f"ΔΙΑΤΗΡΗΣΗ ({context_msg}): Το {fname} είναι πρόσφατο (Ηλικία: {int(age_seconds)}s).")
        if DEBUG: 
            print(f"DEBUG [Keep]: Το {fname} παραμένει στον σέρβερ (Κάτω από 5 λεπτά).")
        return False
        
        
# Πληροφορίες: Επαληθεύει ότι το αρχείο στο QNAP υπάρχει και είναι ακέραιο (Integrity Check).
# ΣΥΝΔΕΣΗ: Είναι το "φίλτρο ασφαλείας" πριν τη διαγραφή. Αν η σύγκριση bytes αποτύχει, 
# το script θεωρεί το τοπικό αρχείο κατεστραμμένο και ΔΕΝ σβήνει το πρωτότυπο.
def verify_local_file(local_path, expected_size):
    """
    ΠΛΗΡΟΦΟΡΙΕΣ: Επαληθεύει ότι το αρχείο στο QNAP υπάρχει και είναι ακέραιο.
    ΣΥΝΔΕΣΗ: Αν το μέγεθος διαφέρει έστω και 1 byte, η συνάρτηση επιστρέφει False 
             και η διαγραφή στον IONOS ακυρώνεται.
    """
    # 1. Έλεγχος αν το αρχείο υπάρχει καν στο δίσκο
    if not os.path.exists(local_path):
        if DEBUG: 
            print(f"DEBUG [Verify]: Το αρχείο {local_path} ΔΕΝ υπάρχει τοπικά.")
        return False

    # 2. Λήψη του πραγματικού μεγέθους από το QNAP
    try:
        actual_size = os.path.getsize(local_path)
    except Exception as e:
        cam_logger.error(f"ΣΦΑΛΜΑ κατά την ανάγνωση μεγέθους του {local_path}: {e}")
        return False

    # 3. Σύγκριση Bytes (Το κρίσιμο σημείο)
    is_valid = (actual_size == expected_size)

    # Αναλυτικό Logging & Debugging
    if is_valid:
        if DEBUG: 
            print(f"DEBUG [Verify]: OK -> {os.path.basename(local_path)} ({actual_size} bytes)")
    else:
        # Αν το μέγεθος διαφέρει, καταγράφουμε το πρόβλημα
        error_msg = f"ΛΑΘΟΣ ΜΕΓΕΘΟΣ: {os.path.basename(local_path)} (Περιμέναμε: {expected_size}, Βρήκαμε: {actual_size})"
        cam_logger.warning(error_msg)
        if DEBUG: 
            print(f"DEBUG [Verify]: {error_msg}")

    return is_valid


# Πληροφορίες: Ο Worker που αναλαμβάνει το κατέβασμα ενός συγκεκριμένου αρχείου.
# ΣΥΝΔΕΣΗ: Κάθε thread ανοίγει τη δική του αυτόνομη σύνδεση SSH/SFTP. 
# Αυτό διασφαλίζει ότι αν μια μεταφορά κολλήσει, δεν θα επηρεάσει τις υπόλοιπες.
def download_file(ssh_params, task):
    """
    ΠΛΗΡΟΦΟΡΙΕΣ: Ο worker που αναλαμβάνει το κατέβασμα ενός συγκεκριμένου αρχείου.
    ΣΥΝΔΕΣΗ: Κάθε worker ανοίγει δική του σύνδεση SFTP για να μην υπάρχουν συγκρούσεις (race conditions).
    """
    # Αποσυσκευασία του task (Προσοχή στη σειρά!)
    remote_path, local_path, expected_size = task
    fname = os.path.basename(remote_path)
    
    transport = None
    try:
        # 1. Δημιουργία αυτόνομης σύνδεσης SSH/SFTP για τον Worker
        transport = paramiko.Transport((ssh_params['host'], 22))
        # Φόρτωση του κλειδιού ειδικά για αυτό το thread
        worker_key = paramiko.Ed25519Key.from_private_key_file(ssh_params['key_path'])
        transport.connect(username=ssh_params['user'], pkey=worker_key, timeout=20)
        # Προσθήκη timeout στο κανάλι για να μην "κρεμάει" το thread
        transport.set_keepalive(30)
        sftp = paramiko.SFTPClient.from_transport(transport)
        
        if DEBUG: print(f"DEBUG [Worker]: Έναρξη σύνδεσης για το {fname}")

        # 2. Λήψη χρόνου τροποποίησης ΠΡΙΝ το κατέβασμα
        # ΣΥΝΔΕΣΗ: Παίρνουμε το st_mtime από τον IONOS για να υπολογίσουμε την ηλικία.
        file_stat = sftp.stat(remote_path)
        age_seconds = datetime.datetime.now().timestamp() - file_stat.st_mtime

        # 3. ΕΝΑΡΞΗ ΜΕΤΑΦΟΡΑΣ
        cam_logger.info(f"ΕΝΑΡΞΗ ΛΗΨΗΣ: {fname} (Αναμενόμενο μέγεθος: {expected_size} bytes)")
        sftp.get(remote_path, local_path)

        # 4. ΕΠΑΛΗΘΕΥΣΗ & ΚΑΘΑΡΙΣΜΟΣ (Η διπλή εγγύηση)
        # Πρώτα ελέγχουμε αν το αρχείο στο QNAP είναι σωστό
        if verify_local_file(local_path, expected_size):
            cam_logger.info(f"ΕΠΙΤΥΧΙΑ: Το αρχείο {fname} αποθηκεύτηκε σωστά στο QNAP.")
            
            # Μόνο αν η επαλήθευση είναι OK, καλούμε τον καθαριστή
            # ΣΥΝΔΕΣΗ: Περνάμε το sftp του worker, το μονοπάτι, την ηλικία και ένα μήνυμα context.
            check_and_remove_remote(sftp, remote_path, age_seconds, "Worker-Flow")
        else:
            # Αν η verify_local_file επιστρέψει False, καταγράφουμε σοβαρό σφάλμα
            cam_logger.error(f"ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: Το {fname} κατέβηκε αλλά η επαλήθευση απέτυχε (Corrupted?).")

    except Exception as e:
        error_msg = f"ΑΠΟΤΥΧΙΑ WORKER για το αρχείο {fname}: {str(e)}"
        cam_logger.error(error_msg)
        if DEBUG: print(f"DEBUG [Worker Error]: {error_msg}")
    
    finally:
        # 5. Κλείσιμο σύνδεσης του Worker οπωσδήποτε
        if transport:
            transport.close()
            if DEBUG: print(f"DEBUG [Worker]: Η σύνδεση για το {fname} έκλεισε.")


def run_camera_sync(ssh, sftp):
    """
    ΠΛΗΡΟΦΟΡΙΕΣ: Ο κεντρικός συντονιστής (Manager) που σαρώνει τον IONOS και αναθέτει εργασίες.
    ΣΥΝΔΕΣΗ: Ελέγχει την ύπαρξη αρχείων στο QNAP και αποφασίζει αν θα γίνει Download ή Cleanup.
    """
    # Καταγραφή έναρξης στο Log
    cam_logger.info("======= ΕΝΑΡΞΗ ΔΙΑΔΙΚΑΣΙΑΣ ΣΥΓΧΡΟΝΙΣΜΟΥ =======")
    # Εκτύπωση στην κονσόλα αν το DEBUG είναι True
    if DEBUG: print("\n[DEBUG-MANAGER] Ξεκινάει η σάρωση των απομακρυσμένων φακέλων...")
    
    # Λίστα που θα κρατήσει τα αρχεία που πρέπει να κατέβουν
    all_tasks = []
    # Λήψη τρέχοντος χρόνου για τον υπολογισμό ηλικίας αρχείων
    now_ts = datetime.datetime.now().timestamp()
    
    try:
        # Διάβασμα των φακέλων (ημερομηνιών) από τον κεντρικό κατάλογο Vigi_Cam
        remote_folders = sftp.listdir(REMOTE_VIGI_DIR)
        if DEBUG: print(f"[DEBUG-MANAGER] Βρέθηκαν {len(remote_folders)} φάκελοι ημερομηνιών.")
    except Exception as e:
        # Καταγραφή σφάλματος αν δεν μπορεί να διαβάσει τον κατάλογο
        cam_logger.error(f"ΣΦΑΛΜΑ: Αποτυχία ανάγνωσης του {REMOTE_VIGI_DIR}: {e}")
        return

    # Επανάληψη για κάθε φάκελο ημερομηνίας (π.χ. 20240518)
    for folder_name in remote_folders:
        # Έλεγχος και στους δύο υποφακέλους: video και picture
        for sub in ['video', 'picture']:
            # Κατασκευή του πλήρους μονοπατιού στον IONOS
            remote_sub = f"{REMOTE_VIGI_DIR}/{folder_name}/{sub}"
            
            try:
                # Λήψη λίστας αρχείων μαζί με τα attributes (μέγεθος, χρόνο τροποποίησης)
                for attr in sftp.listdir_attr(remote_sub):
                    # Αν το αντικείμενο είναι φάκελος και όχι αρχείο, το προσπερνάμε
                    if stat.S_ISDIR(attr.st_mode): 
                        continue
                    
                    # 1. Κατασκευή τοπικής διαδρομής στο QNAP (Έτος/Μήνας/Ημέρα)
                    loc_dir = os.path.join(LOCAL_VIGI_DIR, folder_name[0:4], folder_name[4:6], folder_name[6:8], sub)
                    # 2. Πλήρες μονοπάτι του αρχείου τοπικά
                    local_file_path = os.path.join(loc_dir, attr.filename)
                    # 3. Πλήρες μονοπάτι του αρχείου στον IONOS
                    remote_full_path = f"{remote_sub}/{attr.filename}"

                    # --- ΕΛΕΓΧΟΣ 1: Χρειάζεται κατέβασμα; ---
                    # Καλούμε τη verify_local_file για να δούμε αν το αρχείο λείπει ή είναι κατεστραμμένο
                    if not verify_local_file(local_file_path, attr.st_size):
                        # Αν το αρχείο δεν υπάρχει, δημιουργούμε τον τοπικό φάκελο αν δεν υπάρχει
                        os.makedirs(loc_dir, exist_ok=True)
                        # Προσθήκη του αρχείου στη λίστα εργασιών (Task List)
                        all_tasks.append((remote_full_path, local_file_path, attr.st_size))
                        # Log και Print για τη νέα προσθήκη
                        cam_logger.info(f"ΠΡΟΣΘΗΚΗ: Το αρχείο {attr.filename} μπήκε στην ουρά για λήψη.")
                        if DEBUG: print(f"[DEBUG-QUEUE] {attr.filename} -> Προσθήκη (Λείπει από το QNAP)")
                    
                    # --- ΕΛΕΓΧΟΣ 2: Υπάρχει ήδη στο QNAP, έλεγχος για καθαρισμό ---
                    else:
                        # Υπολογισμός δευτερολέπτων που έχουν περάσει από τη δημιουργία του αρχείου
                        age_now = now_ts - attr.st_mtime
                        # Κλήση της συνάρτησης καθαρισμού με context 'Existing-Flow'
                        check_and_remove_remote(sftp, remote_full_path, age_now, "Existing-Flow")
                        if DEBUG: print(f"[DEBUG-SKIP] {attr.filename} -> Υπάρχει ήδη. Έλεγχος ηλικίας για διαγραφή.")

            except Exception as e:
                # Αν ένας υποφάκελος λείπει (π.χ. δεν υπάρχουν pictures), συνεχίζουμε αθόρυβα
                if DEBUG: print(f"[DEBUG-INFO] Προσπέραση {remote_sub}: {e}")
                continue

    # --- ΕΚΤΕΛΕΣΗ ΜΕΤΑΦΟΡΩΝ ---
    # Αν η λίστα tasks δεν είναι άδεια, ξεκινάμε τους Workers
    if all_tasks:
        cam_logger.info(f"ΣΥΝΟΛΟ ΕΡΓΑΣΙΩΝ: {len(all_tasks)} αρχεία προς μεταφορά.")
        if DEBUG: print(f"\n[DEBUG-EXECUTE] Εκκίνηση {MAX_WORKERS} Workers για {len(all_tasks)} αρχεία...")
        
        # Παραμέτρους σύνδεσης για τους Workers
        # Παραμέτρους σύνδεσης για τους Workers
        ssh_params = {'host': IONOS_IP, 'user': IONOS_USER, 'key_path': SSH_KEY_PATH}
        
        # Χρήση ThreadPool για παράλληλο κατέβασμα
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Κάθε task περνάει στη download_file
            executor.map(lambda t: download_file(ssh_params, t), all_tasks)
    else:
        # Αν δεν βρέθηκε τίποτα νέο
        cam_logger.info("ΑΠΟΤΕΛΕΣΜΑ: Δεν βρέθηκαν νέα αρχεία για λήψη.")
        if DEBUG: print("[DEBUG-RESULT] Όλα τα αρχεία είναι ήδη συγχρονισμένα.")

    # --- ΤΕΛΙΚΟΣ ΚΑΘΑΡΙΣΜΟΣ ΦΑΚΕΛΩΝ ---
    # Εκτέλεση εντολής find για διαγραφή άδειων φακέλων στον IONOS
    cam_logger.info("Εκτέλεση καθαρισμού άδειων φακέλων στον IONOS.")
    if DEBUG: print("[DEBUG-CLEANUP] Διαγραφή άδειων καταλόγων στον IONOS...")
    
    cleanup_cmd = f"sudo /usr/bin/find {REMOTE_VIGI_DIR}/* -type d -empty -delete"
    run_remote_cmd(ssh, cleanup_cmd)
    
    # Καταγραφή τέλους διαδικασίας
    cam_logger.info("======= ΤΕΛΟΣ ΔΙΑΔΙΚΑΣΙΑΣ ΣΥΓΧΡΟΝΙΣΜΟΥ =======")
    if DEBUG: print("[DEBUG-MANAGER] Η διαδικασία ολοκληρώθηκε επιτυχώς.\n")
    
    
# --- MAIN EXECUTION ---
# Main check
# Πληροφορίες: Έναρξη του κυρίου προγράμματος
if __name__ == "__main__":
    # Πληροφορίες: Λήψη της τρέχουσας ημερομηνίας και ώρας
    now = datetime.datetime.now()
    
    # Πληροφορίες: Εξαγωγή της ώρας για τον έλεγχο της λειτουργίας (Backup vs Sync)
    current_hour = now.hour
    
    # Πληροφορίες: Εξαγωγή των λεπτών από το αντικείμενο χρόνου
    # ΣΥΝΔΕΣΗ: Τα λεπτά χρησιμοποιούνται για τον ακριβή συγχρονισμό με το Crontab (55).
    current_minute = now.minute
    
    # Πληροφορίες: Δημιουργία αντικειμένου SSH Client μέσω της βιβλιοθήκης Paramiko
    ssh = paramiko.SSHClient()
    
    # Πληροφορίες: Ρύθμιση αποδοχής άγνωστων κλειδιών host (AutoAddPolicy)
    # ΣΥΝΔΕΣΗ: Απαραίτητο για να μην κολλάει η σύνδεση την πρώτη φορά που συνδέεται στον IONOS.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Πληροφορίες: Δημιουργία μηνύματος έναρξης για το Log και το Debug
    msg = f"ΡΟΗ ΕΝΑΡΞΗΣ --------------> Ώρα: {current_hour:02d}, Λεπτά: {current_minute:02d}"
    
    # Πληροφορίες: Αν η μεταβλητή DEBUG είναι True, εκτύπωση της ροής στην οθόνη
    if DEBUG:
        print(f"DEBUG: {msg}")
        print(f"DEBUG: Προσπάθεια σύνδεσης SSH στο {IONOS_IP}...")
            
    # Πληροφορίες: Έναρξη μπλοκ try για τη διαχείριση σφαλμάτων σύνδεσης
    try:
        # Πληροφορίες: Πραγματοποίηση της σύνδεσης SSH στον IONOS
        # Φόρτωση του συγκεκριμένου Ed25519 κλειδιού
        private_key = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)
    
        # Σύνδεση χρησιμοποιώντας το pkey - Προσθήκη timeout και απενεργοποίηση αναζήτησης άλλων κλειδιών
        ssh.connect(
                hostname=IONOS_IP, 
                username=IONOS_USER, 
                pkey=private_key,
                timeout=15,             # Σταματάει αν δεν απαντήσει ο σέρβερ σε 15"
                look_for_keys=False,     # Μην ψάχνεις άλλα κλειδιά στο σύστημα
                allow_agent=False        # Μην χρησιμοποιείς SSH Agent
            )
        # Πληροφορίες: Καταγραφή της επιτυχούς σύνδεσης στο log
        sys_logger.info("Σύνδεση επιτυχής με το Ed25519 κλειδί.")

        if DEBUG:
            print(f"DEBUG: Σύνδεση επιτυχής με το Ed25519 κλειδί. Ανοίγω κανάλι SFTP...")

        # Πληροφορίες: Δημιουργία καναλιού SFTP για τη μεταφορά αρχείων
        sftp = ssh.open_sftp()
        
        # Πληροφορίες: Ενημέρωση του log για την ετοιμότητα του SFTP
        sys_logger.info("Το κανάλι SFTP ανοίχτηκε με επιτυχία.")
        
        if DEBUG: 
            print("DEBUG: Το SFTP είναι ενεργό και έτοιμο.")

        # Πληροφορίες: Έλεγχος αν η ώρα είναι 22:55 για την εκτέλεση του Full Backup
        # ΣΥΝΔΕΣΗ: Συνδέουμε τον χρόνο του συστήματος με τη βαριά εργασία συντήρησης.
        # if True:
        if current_hour == 23 and current_minute == 55:
            # Πληροφορίες: Καταγραφή έναρξης Full Backup
            sys_logger.info(f"--- ΕΝΑΡΞΗ FULL BACKUP --- {msg}")
            if DEBUG:
                print(f"DEBUG: Ενεργοποίηση perform_full_system_backup")
            # Πληροφορίες: Κλήση της συνάρτησης για το πλήρες backup
            perform_full_system_backup(ssh, sftp)
        
        # Πληροφορίες: Σε κάθε άλλη περίπτωση, εκτελείται ο γρήγορος συγχρονισμός καμερών
        # ΣΥΝΔΕΣΗ: Χρησιμοποιούμε το cam_logger για να διαχωρίζουμε τη δραστηριότητα στο κοινό log.
        log_sync = f"Η ώρα είναι {current_hour:02d}:{current_minute:02d}. Έναρξη συγχρονισμού καμερών."
        cam_logger.info(log_sync)
        if DEBUG:
            print(f"DEBUG: {log_sync}")
        # Πληροφορίες: Κλήση της συνάρτησης για το συγχρονισμό των αρχείων καμερών
        run_camera_sync(ssh, sftp)

        # Πληροφορίες: Κλείσιμο του καναλιού SFTP
        # ΣΥΝΔΕΣΗ: Πρέπει να κλείνει πάντα για να μην μένουν ανοιχτά sessions στον IONOS.
        sftp.close()
        # Πληροφορίες: Κλείσιμο της σύνδεσης SSH
        ssh.close()
        sys_logger.info(f"Οι συνδέσεις SSH/SFTP έκλεισαν κανονικά. Τέλος προγράμματος.")
        if DEBUG:
            print("DEBUG: Οι συνδέσεις SSH/SFTP έκλεισαν κανονικά. Τέλος προγράμματος.")

    # Πληροφορίες: Διαχείριση οποιουδήποτε σφάλματος προκύψει κατά την εκτέλεση
    # ΣΥΝΔΕΣΗ: Εδώ θα "πιάσουμε" προβλήματα δικτύου ή λανθασμένα δικαιώματα.
    except Exception as e:
        error_msg = f"ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: {str(e)}"
        # Πληροφορίες: Καταγραφή του σφάλματος στο Log
        sys_logger.error(error_msg)
        # Πληροφορίες: Αν το DEBUG είναι True, εκτύπωση του σφάλματος στην οθόνη
        if DEBUG: 
            print(f"DEBUG [ERROR]: {error_msg}")
        
        # Κλήση της συνάρτησης email
        send_error_email(error_msg)
