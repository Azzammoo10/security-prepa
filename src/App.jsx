import React, { useState } from 'react';
import { Book, Shield, Lock, AlertTriangle, Network, Bug, Eye, Server, Users, CheckCircle, Terminal, Cpu, Fingerprint } from 'lucide-react';

const SecurityStudyGuide = () => {
  const [activeChapter, setActiveChapter] = useState(1);
  const [expandedSections, setExpandedSections] = useState({});

  const toggleSection = (id) => {
    setExpandedSections(prev => ({...prev, [id]: !prev[id]}));
  };

  const chapters = [
    {
      id: 1,
      title: "Bases SI & SSI",
      icon: Book,
      color: "from-cyan-500 to-blue-600",
      sections: [
        {
          id: "si",
          title: "🖥️ SI - Système d'Information",
          content: "Ensemble organisé de ressources (matériel, logiciel, données, procédures, personnes) permettant de collecter, traiter, stocker et diffuser l'information dans une organisation",
          examples: [
            "💻 Matériel: Serveurs, postes de travail, équipements réseau",
            "📱 Logiciels: Applications métier, systèmes d'exploitation, SGBD",
            "📊 Données: Bases de données, fichiers, documents",
            "👥 Utilisateurs: Personnel, clients, partenaires",
            "⚙️ Processus: Procédures, règles de gestion"
          ],
          formula: "SI = Matériel + Logiciel + Données + Utilisateurs + Procédures"
        },
        {
          id: "ssi",
          title: "🛡️ SSI - Sécurité des SI",
          content: "Ensemble des moyens techniques, organisationnels, juridiques et humains pour protéger le SI contre les menaces internes et externes. Objectif: garantir la triade CIA (Confidentialité, Intégrité, Disponibilité)",
          examples: [
            "🔥 Pare-feu: Filtre le trafic réseau entrant/sortant",
            "🔐 Chiffrement: Rend les données illisibles sans clé",
            "🦠 Antivirus/EDR: Détecte et bloque les malwares",
            "🚪 Contrôle d'accès: Authentification + autorisation",
            "📝 Logs & monitoring: Surveillance continue",
            "💾 Sauvegardes: Récupération en cas d'incident"
          ],
          formula: "SSI = Prévention + Détection + Réaction + Récupération"
        },
        {
          id: "classification",
          title: "📋 Classification Sécurité",
          content: "4 couches de protection complémentaires formant une défense en profondeur (Defense in Depth)",
          examples: [
            "🏢 Sécurité Physique:",
            "  • Contrôle d'accès: badges, biométrie, sas",
            "  • Surveillance: caméras, gardiennage",
            "  • Protection: armoires sécurisées, salles blanches",
            "",
            "💻 Sécurité Informatique:",
            "  • Authentification: MFA, mots de passe forts",
            "  • Antimalware: antivirus, EDR, sandboxing",
            "  • Gestion des accès: RBAC, moindre privilège",
            "",
            "📡 Sécurité des Communications:",
            "  • Chiffrement: VPN, SSL/TLS, IPSec",
            "  • Segmentation: VLANs, DMZ, firewall",
            "  • Protocoles sécurisés: HTTPS, SFTP, SSH",
            "",
            "⚙️ Sécurité Opérationnelle:",
            "  • Processus: PCA/PRA, gestion des incidents",
            "  • Formation: sensibilisation utilisateurs",
            "  • Audits: tests d'intrusion, revues de code"
          ],
          formula: "Sécurité globale = Physique ∩ Informatique ∩ Communications ∩ Opérationnelle"
        },
        {
          id: "cyberattaques",
          title: "⚠️ Cyberattaques Courantes",
          content: "Panorama des menaces cyber les plus fréquentes en 2024-2026",
          examples: [
            "🎣 Phishing (Hameçonnage):",
            "  • Email/SMS frauduleux imitant une entité légitime",
            "  • But: voler identifiants, coordonnées bancaires",
            "  • Variantes: Spear phishing (ciblé), Whaling (dirigeants)",
            "",
            "🔐 Ransomware (Rançongiciel):",
            "  • Chiffre les fichiers de la victime",
            "  • Demande rançon en crypto-monnaie",
            "  • Exemples: WannaCry, Locky, CryptoLocker",
            "",
            "👤 Usurpation d'Identité:",
            "  • Vol de credentials (login/password)",
            "  • Techniques: Keylogging, credential stuffing",
            "  • Impact: accès non autorisé, fraude",
            "",
            "🦱 Malwares Avancés:",
            "  • Trojans: backdoors, espionnage",
            "  • Spywares: capture de données sensibles",
            "  • Rootkits: contrôle profond du système",
            "",
            "🌐 Attaques DDoS:",
            "  • Saturation de ressources (bande passante, CPU)",
            "  • Botnets: réseaux d'appareils compromis",
            "  • Impact: indisponibilité du service"
          ],
          formula: "Vecteurs principaux: Email (54%) > Web (20%) > Réseau (15%) > Physique (11%)"
        }
      ]
    },
    {
      id: 2,
      title: "Risques & Menaces",
      icon: AlertTriangle,
      color: "from-red-500 to-pink-600",
      sections: [
        {
          id: "vuln",
          title: "🚪 Vulnérabilité = Porte Ouverte",
          content: "Faiblesse ou faille dans un système qui peut être exploitée par une menace. C'est comme laisser une fenêtre ouverte chez soi.",
          examples: [
            "🔑 Mot de passe faible: 123456, admin, date de naissance",
            "🔄 Logiciel non à jour: failles de sécurité non corrigées (CVE)",
            "🚫 Absence de contrôle: pas de validation des entrées",
            "👤 Erreur humaine: clic sur lien malveillant, divulgation d'info",
            "⚙️ Configuration: ports ouverts, services inutiles actifs",
            "📝 Code: buffer overflow, injection SQL possible"
          ],
          formula: "Vulnérabilité = Faille technique + Faille humaine + Faille organisationnelle"
        },
        {
          id: "menace",
          title: "👹 Menace = Exploitation",
          content: "Agent (personne, logiciel, événement) qui cherche à exploiter une vulnérabilité pour nuire au système",
          examples: [
            "👨‍💻 Pirate informatique (Hacker): black hat, script kiddie",
            "🦠 Virus/Malware: programme malveillant automatisé",
            "⚡ Coupure de courant: menace environnementale",
            "👔 Employé malveillant: insider threat, vol de données",
            "🌊 Catastrophe naturelle: inondation, incendie",
            "🕵️ APT: Advanced Persistent Threat (attaque ciblée longue durée)"
          ],
          formula: "Menace = Intention malveillante + Capacité d'action + Opportunité"
        },
        {
          id: "risque",
          title: "💥 Risque = Conséquence",
          content: "Probabilité qu'une menace exploite une vulnérabilité et cause un impact sur le système",
          examples: [
            "💰 Vol de données: fuite d'informations confidentielles",
            "⏸️ Arrêt de service: indisponibilité, perte de productivité",
            "💸 Perte financière: amendes RGPD, perte de revenus",
            "😔 Réputation: perte de confiance clients",
            "⚖️ Juridique: poursuites, non-conformité"
          ],
          formula: "Risque = (Menace × Vulnérabilité × Impact) / Contre-mesure | R = P × I (Probabilité × Impact)"
        },
        {
          id: "matrice",
          title: "📊 Matrice des Risques 5×5",
          content: "Outil d'évaluation visuelle: Impact (Y) × Probabilité/Fréquence (X). Permet de prioriser les risques à traiter",
          examples: [
            "Axes de la matrice:",
            "• X (Probabilité): Très rare → Très fréquent (1-5)",
            "• Y (Impact): Négligeable → Catastrophique (1-5)",
            "",
            "Classification des risques:",
            "🟢 FAIBLE (1-4): Impact faible + rare",
            "  → Action: Accepter ou surveiller",
            "🟡 MOYEN (5-12): Impact moyen OU fréquent",
            "  → Action: Réduire ou transférer",
            "🟠 ÉLEVÉ (13-19): Impact important",
            "  → Action: Traiter en priorité",
            "🔴 CRITIQUE (20-25): Impact fort + fréquent",
            "  → Action: Urgence absolue, plan d'action immédiat",
            "",
            "Exemples concrets:",
            "• Phishing ciblé: P=4, I=5 → Score=20 (CRITIQUE)",
            "• Panne matériel: P=2, I=3 → Score=6 (MOYEN)",
            "• Bug mineur: P=3, I=1 → Score=3 (FAIBLE)"
          ],
          formula: "Score = Probabilité × Impact | Seuil critique: ≥15"
        },
        {
          id: "types-attaques",
          title: "🎯 4 Types d'Attaques",
          content: "Classification selon l'objectif et l'impact sur les ressources du système",
          examples: [
            "🚫 INTERRUPTION (Disponibilité):",
            "  • Objectif: Rendre une ressource indisponible",
            "  • Exemples: DoS/DDoS, destruction de matériel",
            "  • Impact: Perte de service, arrêt d'activité",
            "  • Contre-mesure: Redondance, anti-DDoS, PRA",
            "",
            "👂 INTERCEPTION (Confidentialité):",
            "  • Objectif: Espionner, capturer des données",
            "  • Exemples: MITM, Sniffing, Écoute réseau",
            "  • Impact: Fuite d'informations sensibles",
            "  • Contre-mesure: Chiffrement (SSL/TLS, VPN)",
            "",
            "🎭 FABRICATION (Authenticité):",
            "  • Objectif: Créer de fausses informations",
            "  • Exemples: Phishing, Spoofing, faux emails",
            "  • Impact: Usurpation d'identité, tromperie",
            "  • Contre-mesure: Signatures numériques, SPF/DKIM",
            "",
            "✏️ MODIFICATION (Intégrité):",
            "  • Objectif: Altérer des données ou du code",
            "  • Exemples: SQL Injection, XSS, Buffer Overflow",
            "  • Impact: Corruption de données, exécution de code",
            "  • Contre-mesure: Validation entrées, WAF, Hash"
          ],
          formula: "Chaque type cible un pilier de sécurité différent (D, C, A, I)"
        }
      ]
    },
    {
      id: 3,
      title: "Objectifs & Attaques",
      icon: Shield,
      color: "from-green-500 to-emerald-600",
      sections: [
        {
          id: "candi",
          title: "🎯 CANDI - Les 5 Piliers",
          content: "Objectifs fondamentaux de la sécurité informatique. Acronyme essentiel à mémoriser : CANDI ou CIA/DIC en anglais",
          examples: [
            "🔒 CONFIDENTIALITÉ:",
            "  • Définition: Seules les personnes autorisées accèdent à l'info",
            "  • Techniques: Chiffrement, contrôle d'accès, classification",
            "  • Exemple: Dossier médical accessible uniquement au médecin",
            "  • Menaces: Sniffing, phishing, accès non autorisé",
            "",
            "✅ AUTHENTIFICATION:",
            "  • Définition: Prouver son identité de manière fiable",
            "  • Techniques: MFA (something you know/have/are)",
            "  • Exemple: Mot de passe + code SMS + empreinte digitale",
            "  • Menaces: Brute force, credential stuffing, social engineering",
            "",
            "📝 NON-RÉPUDIATION:",
            "  • Définition: Impossible de nier avoir effectué une action",
            "  • Techniques: Signature numérique, logs horodatés, blockchain",
            "  • Exemple: Email signé numériquement, transaction bancaire",
            "  • Importance: Preuve juridique, traçabilité",
            "",
            "⚡ DISPONIBILITÉ:",
            "  • Définition: Service accessible quand nécessaire",
            "  • Techniques: Redondance, load balancing, PRA/PCA",
            "  • Exemple: Site e-commerce accessible 24/7/365",
            "  • Menaces: DoS/DDoS, pannes matérielles, ransomware",
            "",
            "🔐 INTÉGRITÉ:",
            "  • Définition: Données non modifiées de manière non autorisée",
            "  • Techniques: Hash (SHA-256), checksum, HMAC",
            "  • Exemple: Fichier téléchargé vérifié par hash",
            "  • Menaces: SQL Injection, XSS, man-in-the-middle"
          ],
          formula: "CANDI = CIA (Confidentiality, Integrity, Availability) + Authentication + Non-repudiation"
        },
        {
          id: "attaques-types",
          title: "🔍 Typologie des Attaques",
          content: "Classification selon l'origine (interne/externe) et le mode opératoire (passive/active)",
          examples: [
            "👨‍💼 ATTAQUES INTERNES (Insider Threats):",
            "  • Origine: Employé, prestataire, partenaire",
            "  • Motivations: Vengeance, gain financier, négligence",
            "  • Exemples: Vol de données, sabotage, installation backdoor",
            "  • Danger: Accès légitime + connaissance du SI",
            "  • Statistiques: 34% des incidents de sécurité",
            "",
            "🌐 ATTAQUES EXTERNES:",
            "  • Origine: Internet, réseau public",
            "  • Acteurs: Hackers, cybercriminels, États",
            "  • Exemples: DoS/DDoS, DHCP Spoofing, exploitation vulnérabilités",
            "  • Protection: Firewall, IDS/IPS, segmentation réseau",
            "",
            "👁️ ATTAQUES PASSIVES (Écoute):",
            "  • Objectif: Observer sans modifier (stealthy)",
            "  • Techniques: Sniffing réseau, analyse de trafic",
            "  • Difficulté: Très difficiles à détecter",
            "  • Impact: Compromission de la confidentialité",
            "  • Contre-mesure: Chiffrement end-to-end",
            "",
            "⚔️ ATTAQUES ACTIVES (Modification):",
            "  • Objectif: Modifier ou perturber le système",
            "  • Techniques: SQL Injection, XSS, CSRF, Buffer Overflow",
            "  • Détection: Plus facile (logs, IDS, anomalies)",
            "  • Impact: Intégrité et disponibilité compromises",
            "  • Contre-mesure: WAF, validation entrées, monitoring"
          ],
          formula: "Attaque = [Interne ∪ Externe] × [Passive ∪ Active]"
        },
        {
          id: "attaques-candi",
          title: "🎯 Attaques par Fonction CANDI",
          content: "Cartographie des attaques selon le pilier de sécurité ciblé",
          examples: [
            "🔒 Attaques contre CONFIDENTIALITÉ:",
            "  • Sniffing: Capture de paquets réseau (Wireshark)",
            "  • Phishing: Vol d'identifiants via email frauduleux",
            "  • Scan de ports: Nmap pour découvrir services exposés",
            "  • Shoulder surfing: Observer l'écran/clavier",
            "  • Dumpster diving: Fouille de poubelles pour infos",
            "",
            "✅ Attaques contre AUTHENTIFICATION:",
            "  • Brute force: Test systématique de mots de passe",
            "  • Dictionary attack: Utilise liste de mots communs",
            "  • Usurpation IP/MAC: Spoofing d'adresse réseau",
            "  • ARP Poisoning: Redirection trafic réseau",
            "  • Pass-the-Hash: Réutilisation de hash sans mot de passe",
            "",
            "📝 Attaques contre NON-RÉPUDIATION:",
            "  • DHCP Starvation: Épuisement du pool DHCP",
            "  • DHCP Spoofing: Faux serveur DHCP",
            "  • Log tampering: Modification des journaux",
            "  • Replay attack: Réutilisation de messages valides",
            "",
            "⚡ Attaques contre DISPONIBILITÉ:",
            "  • DoS: Denial of Service depuis une source",
            "  • DDoS: Attaque distribuée (botnet)",
            "  • Smurf attack: Amplification via ICMP broadcast",
            "  • SYN Flood: Saturation avec requêtes TCP SYN",
            "  • Fork bomb: Épuisement ressources système",
            "",
            "🔐 Attaques contre INTÉGRITÉ:",
            "  • SQL Injection: Injection code dans requête SQL",
            "  • XSS: Cross-Site Scripting, injection JavaScript",
            "  • Buffer Overflow: Dépassement de tampon mémoire",
            "  • CSRF: Cross-Site Request Forgery",
            "  • Man-in-the-Middle: Interception + modification"
          ],
          formula: "Attaque → Pilier CANDI ciblé → Impact spécifique"
        },
        {
          id: "protections",
          title: "🛡️ Moyens de Protection CANDI",
          content: "Contre-mesures adaptées à chaque pilier de sécurité",
          examples: [
            "🔒 Protéger la CONFIDENTIALITÉ:",
            "  • SSL/TLS: Chiffrement des communications HTTPS",
            "  • VPN (IPSec, OpenVPN): Tunnel chiffré",
            "  • PGP/GPG: Chiffrement d'emails",
            "  • BitLocker/LUKS: Chiffrement de disque",
            "  • Classification: Public, Interne, Confidentiel, Secret",
            "",
            "✅ Renforcer l'AUTHENTIFICATION:",
            "  • MFA/2FA: Multi-facteurs (SMS, TOTP, biométrie)",
            "  • Mots de passe forts: 12+ caractères, complexité",
            "  • Gestionnaire: LastPass, 1Password, KeePass",
            "  • Kerberos: Authentification centralisée",
            "  • Certificats: PKI, authentification mutuelle TLS",
            "",
            "📝 Garantir la NON-RÉPUDIATION:",
            "  • Signature numérique: RSA, ECDSA",
            "  • Horodatage: TSA (Time Stamping Authority)",
            "  • Logs centralisés: SIEM, syslog sécurisé",
            "  • Blockchain: Registre immuable distribué",
            "  • PKI: Infrastructure à clés publiques",
            "",
            "⚡ Assurer la DISPONIBILITÉ:",
            "  • Pare-feu: Filtrage trafic entrant/sortant",
            "  • Anti-DDoS: Cloudflare, Arbor Networks",
            "  • Backups 3-2-1: 3 copies, 2 supports, 1 hors site",
            "  • Redondance: RAID, clustering, load balancing",
            "  • PRA/PCA: Plans de reprise/continuité d'activité",
            "",
            "🔐 Préserver l'INTÉGRITÉ:",
            "  • Hash: SHA-256, SHA-3 pour vérifier intégrité",
            "  • HMAC: Hash avec clé secrète",
            "  • Validation entrées: Sanitization, whitelist",
            "  • WAF: Web Application Firewall (ModSecurity)",
            "  • Mises à jour: Patchs de sécurité réguliers",
            "  • Code signing: Signature de logiciels"
          ],
          formula: "Défense en profondeur: Plusieurs couches de protection complémentaires"
        }
      ]
    },
    {
      id: 4,
      title: "Cryptographie",
      icon: Lock,
      color: "from-purple-500 to-indigo-600",
      sections: [
        {
          id: "sym",
          title: "🔑 Chiffrement Symétrique",
          content: "Une seule clé secrète partagée pour chiffrer ET déchiffrer. Rapide mais nécessite échange sécurisé de la clé.",
          examples: [
            "🔐 Algorithmes courants:",
            "  • AES (Advanced Encryption Standard): 128/192/256 bits",
            "  • DES (Data Encryption Standard): obsolète, 56 bits",
            "  • 3DES (Triple DES): 168 bits, lent",
            "  • Blowfish: 32-448 bits, rapide",
            "  • ChaCha20: Moderne, mobile-friendly",
            "",
            "✅ Avantages:",
            "  • Très rapide: idéal pour grandes quantités de données",
            "  • Faible charge CPU: chiffrement en temps réel",
            "  • Simplicité: un seul algorithme, une clé",
            "",
            "❌ Inconvénients:",
            "  • Problème d'échange de clé: canal sécurisé nécessaire",
            "  • Gestion des clés: n(n-1)/2 clés pour n utilisateurs",
            "  • Scalabilité: difficile pour grand nombre d'utilisateurs",
            "",
            "💡 Cas d'usage:",
            "  • Chiffrement de disque (BitLocker, FileVault)",
            "  • VPN (IPSec, OpenVPN)",
            "  • Communication après échange de clé (TLS session)"
          ],
          formula: "Alice & Bob partagent K → E_K(message) = chiffré → D_K(chiffré) = message"
        },
        {
          id: "asym",
          title: "🔐 Chiffrement Asymétrique",
          content: "Deux clés liées mathématiquement: clé publique (diffusable) pour chiffrer, clé privée (secrète) pour déchiffrer",
          examples: [
            "🔑 Algorithmes principaux:",
            "  • RSA: 2048-4096 bits, basé sur factorisation",
            "  • ECC (Elliptic Curve): 256 bits = RSA 3072 bits",
            "  • Diffie-Hellman: Échange de clés",
            "  • ElGamal: Chiffrement et signature",
            "",
            "✅ Avantages:",
            "  • Pas d'échange de clé secrète: clé publique diffusable",
            "  • Scalabilité: 2 clés par utilisateur (publique + privée)",
            "  • Signature numérique: authentification + non-répudiation",
            "",
            "❌ Inconvénients:",
            "  • Très lent: 100-1000x plus lent que symétrique",
            "  • Vulnérable MITM: attaquant peut substituer clé publique",
            "  • Taille de clé: RSA nécessite 2048+ bits",
            "  • Ordinateurs quantiques: menace future (algorithme de Shor)",
            "",
            "💡 Cas d'usage:",
            "  • SSL/TLS: Handshake initial (puis symétrique pour data)",
            "  • Email sécurisé: PGP/GPG",
            "  • Signature de logiciels: Code signing",
            "  • SSH: Authentification par clé publique",
            "",
            "🔄 Hybride (meilleure approche):",
            "  1. Asymétrique: échanger une clé symétrique (session key)",
            "  2. Symétrique: chiffrer les données avec session key",
            "  → Combine rapidité + sécurité de l'échange"
          ],
          formula: "Bob: (pub_B, priv_B) | Alice chiffre avec pub_B → seul priv_B déchiffre"
        },
        {
          id: "hash",
          title: "# Fonctions de Hachage",
          content: "Transformation unidirectionnelle (one-way) produisant une empreinte numérique de taille fixe. Impossible de retrouver le message original.",
          examples: [
            "🔢 Algorithmes de hachage:",
            "  • SHA-256 (Secure Hash Algorithm): 256 bits, standard actuel",
            "  • SHA-3: Nouvelle génération, structure différente",
            "  • MD5: 128 bits, OBSOLÈTE (collisions trouvées)",
            "  • SHA-1: 160 bits, DÉPRÉCIÉ (vulnérable)",
            "  • BLAKE2: Rapide, moderne, concurrent SHA-3",
            "",
            "📏 Propriétés essentielles:",
            "  • Déterministe: même entrée → même hash",
            "  • Rapide à calculer: hash(message) en millisecondes",
            "  • Unidirectionnel: hash → message IMPOSSIBLE",
            "  • Résistance aux collisions: 2 messages ≠ même hash",
            "  • Effet avalanche: 1 bit change → 50% du hash change",
            "  • Taille fixe: peu importe la taille d'entrée",
            "",
            "💡 Cas d'usage:",
            "  • Stockage mots de passe: bcrypt(password + salt)",
            "  • Vérification intégrité: SHA256(fichier) = checksum",
            "  • Blockchain: Proof of Work, chaînage de blocs",
            "  • Signatures numériques: sign(hash(message))",
            "  • Détection de modifications: Git commits",
            "",
            "⚠️ Attaques:",
            "  • Rainbow tables: Précalcul de hash communs",
            "  • Collision: Trouver 2 messages avec même hash",
            "  • Protection: Salt (valeur aléatoire ajoutée)",
            "",
            "🧂 Salt & Pepper:",
            "  • Salt: Valeur aléatoire unique par utilisateur",
            "  • Pepper: Secret global côté serveur",
            "  • Hash final: bcrypt(password + salt) + pepper"
          ],
          formula: "h(message) = empreinte fixe | h(m1) ≠ h(m2) si m1 ≠ m2"
        },
        {
          id: "signature",
          title: "✍️ Signature Numérique",
          content: "Prouve l'authenticité de l'expéditeur ET l'intégrité du message. Équivalent numérique d'une signature manuscrite + sceau.",
          examples: [
            "🔐 Processus de signature:",
            "  1. Hacher le message: h = hash(message)",
            "  2. Chiffrer le hash avec clé PRIVÉE: sig = encrypt_priv(h)",
            "  3. Joindre signature au message: (message, sig)",
            "",
            "✅ Vérification:",
            "  1. Déchiffrer signature avec clé PUBLIQUE: h' = decrypt_pub(sig)",
            "  2. Hacher le message reçu: h = hash(message)",
            "  3. Comparer: h == h' → signature valide ✓",
            "",
            "🎯 Garanties offertes:",
            "  • Authentification: Seul le détenteur de la clé privée peut signer",
            "  • Intégrité: Modification détectée (hash change)",
            "  • Non-répudiation: Impossible de nier avoir signé",
            "",
            "📝 Algorithmes:",
            "  • RSA: Sign avec privé, verify avec public",
            "  • DSA (Digital Signature Algorithm)",
            "  • ECDSA (Elliptic Curve DSA): Plus court",
            "  • EdDSA: Moderne, Ed25519",
            "",
            "💡 Applications:",
            "  • Emails signés: S/MIME, PGP",
            "  • Documents PDF: Adobe Digital Signatures",
            "  • Code signing: Logiciels, drivers Windows",
            "  • Certificats SSL: CA signe les certificats",
            "  • Blockchain: Transactions Bitcoin signées",
            "  • Contrats intelligents: Smart contracts"
          ],
          formula: "Signature = Encrypt_PrivKey(Hash(Message)) | Verify: Decrypt_PubKey(Sig) == Hash(Message)"
        },
        {
          id: "pki",
          title: "🏢 PKI & Autorités de Certification",
          content: "Infrastructure à Clés Publiques: système de confiance pour gérer, distribuer et révoquer des certificats numériques",
          examples: [
            "🏛️ Composants de la PKI:",
            "",
            "CA (Certificate Authority):",
            "  • Rôle: Délivre et signe les certificats numériques",
            "  • Exemples: DigiCert, Let's Encrypt, VeriSign",
            "  • Hiérarchie: Root CA → Intermediate CA → End Entity",
            "  • Confiance: CA racine pré-installée dans navigateurs/OS",
            "",
            "RA (Registration Authority):",
            "  • Rôle: Vérifie l'identité des demandeurs",
            "  • Processus: Validation domaine/organisation/étendue",
            "  • Transmet requêtes validées à la CA",
            "",
            "CRL (Certificate Revocation List):",
            "  • Liste publique des certificats révoqués",
            "  • Raisons: Clé compromise, changement d'info, cessation",
            "  • Mise à jour: Périodique (problème de fraîcheur)",
            "",
            "OCSP (Online Certificate Status Protocol):",
            "  • Alternative à CRL: vérification en temps réel",
            "  • Requête: Is cert #12345 still valid?",
            "  • Réponse: Good / Revoked / Unknown",
            "",
            "Repository (Annuaire):",
            "  • Base de données: Certificats publics, CRL",
            "  • Protocole d'accès: LDAP, HTTP",
            "",
            "📜 Contenu d'un certificat X.509:",
            "  • Version, numéro de série unique",
            "  • Algorithme de signature (SHA256withRSA)",
            "  • Émetteur (CA)",
            "  • Sujet (propriétaire): CN=example.com",
            "  • Clé publique du sujet",
            "  • Dates validité (notBefore, notAfter)",
            "  • Extensions: SAN, Key Usage, Extended Key Usage",
            "  • Signature de la CA",
            "",
            "🔐 Types de certificats SSL/TLS:",
            "  • DV (Domain Validation): Vérification domaine seulement",
            "  • OV (Organization Validation): + vérification entreprise",
            "  • EV (Extended Validation): Vérification poussée, barre verte",
            "  • Wildcard: *.example.com (tous les sous-domaines)",
            "  • SAN/Multi-domain: Plusieurs domaines dans 1 certificat",
            "",
            "🔄 Cycle de vie:",
            "  1. Génération paire de clés (privée + publique)",
            "  2. CSR (Certificate Signing Request) → RA/CA",
            "  3. Validation identité",
            "  4. Émission certificat signé par CA",
            "  5. Installation sur serveur",
            "  6. Renouvellement (avant expiration)",
            "  7. Révocation si compromise"
          ],
          formula: "Chaîne de confiance: Root CA → Intermediate CA → Server Certificate"
        }
      ]
    },
    {
      id: 5,
      title: "Gestion des Risques",
      icon: CheckCircle,
      color: "from-orange-500 to-yellow-600",
      sections: [
        {
          id: "ebios",
          title: "📋 EBIOS - Méthodologie Française",
          content: "Expression des Besoins et Identification des Objectifs de Sécurité. Méthode de l'ANSSI pour l'analyse et le traitement des risques numériques",
          examples: [
            "📖 Les 5 modules EBIOS Risk Manager:",
            "",
            "Module 1 - Cadrage et socle de sécurité:",
            "  • Définir le périmètre (système étudié)",
            "  • Identifier les parties prenantes",
            "  • Établir le socle de sécurité de base",
            "  • Valider les objectifs de l'étude",
            "",
            "Module 2 - Sources de risque:",
            "  • Identifier les acteurs malveillants (cybercriminels, États, concurrents)",
            "  • Évaluer leurs ressources et motivations",
            "  • Cartographier l'écosystème de menaces",
            "",
            "Module 3 - Événements redoutés:",
            "  • Identifier les biens essentiels à protéger",
            "  • Définir les impacts métier redoutés",
            "  • Estimer la gravité (échelle de 1 à 4)",
            "  • Ex: Fuite de données clients → Impact réputation",
            "",
            "Module 4 - Scénarios opérationnels:",
            "  • Construire les chemins d'attaque réalistes",
            "  • Identifier vulnérabilités techniques exploitables",
            "  • Évaluer vraisemblance (probabilité d'occurrence)",
            "  • Cartographier: Source → Chemin d'attaque → Événement redouté",
            "",
            "Module 5 - Traitement du risque:",
            "  • Évaluer le niveau de risque (gravité × vraisemblance)",
            "  • Prioriser les risques à traiter",
            "  • Définir stratégie: Réduire / Transférer / Accepter / Éviter",
            "  • Planifier les mesures de sécurité",
            "  • Suivre et réévaluer périodiquement"
          ],
          formula: "Risque = Gravité(Impact) × Vraisemblance(Probabilité) - Mesures de sécurité"
        },
        {
          id: "iso27001",
          title: "🏆 ISO 27001 - SMSI",
          content: "Norme internationale pour le Système de Management de la Sécurité de l'Information. Certification reconnue mondialement.",
          examples: [
            "🔄 Cycle PDCA (Roue de Deming):",
            "",
            "PLAN (Planifier):",
            "  • Définir la politique de sécurité",
            "  • Identifier les risques (appréciation)",
            "  • Sélectionner les contrôles (Annexe A: 93 contrôles)",
            "  • Établir le plan de traitement des risques",
            "",
            "DO (Déployer):",
            "  • Mettre en œuvre les contrôles",
            "  • Former le personnel",
            "  • Déployer les outils techniques",
            "  • Documenter les procédures",
            "",
            "CHECK (Vérifier):",
            "  • Audits internes réguliers",
            "  • Revues de direction",
            "  • Surveillance et mesure (KPI, métriques)",
            "  • Tests d'efficacité des contrôles",
            "",
            "ACT (Améliorer):",
            "  • Actions correctives sur les non-conformités",
            "  • Actions préventives",
            "  • Amélioration continue du SMSI",
            "  • Mise à jour après incidents",
            "",
            "🎯 Objectifs de l'ISO 27001:",
            "  • Protéger la Confidentialité des informations",
            "  • Garantir l'Intégrité des données",
            "  • Assurer la Disponibilité des services",
            "",
            "📋 Annexe A - 14 domaines de contrôles:",
            "  A.5 Politiques de sécurité",
            "  A.6 Organisation de la sécurité",
            "  A.7 Sécurité des ressources humaines",
            "  A.8 Gestion des actifs",
            "  A.9 Contrôle d'accès",
            "  A.10 Cryptographie",
            "  A.11 Sécurité physique et environnementale",
            "  A.12 Sécurité des opérations",
            "  A.13 Sécurité des communications",
            "  A.14 Acquisition, développement et maintenance",
            "  A.15 Relations avec les fournisseurs",
            "  A.16 Gestion des incidents",
            "  A.17 Continuité d'activité",
            "  A.18 Conformité",
            "",
            "🏅 Certification:",
            "  • Audit de certification par organisme accrédité",
            "  • Validité: 3 ans avec audits de surveillance annuels",
            "  • Démontre engagement et maturité sécurité"
          ],
          formula: "SMSI = PDCA continu + Approche par les risques + Amélioration continue"
        },
        {
          id: "iso27005",
          title: "📊 ISO 27005 - Gestion des Risques",
          content: "Guide des bonnes pratiques pour la gestion des risques de sécurité de l'information. Complément de l'ISO 27001.",
          examples: [
            "🔍 Processus de gestion des risques:",
            "",
            "1️⃣ Établir le contexte:",
            "  • Périmètre: Quels actifs protéger?",
            "  • Critères d'évaluation des risques",
            "  • Critères d'acceptation du risque (seuil)",
            "",
            "2️⃣ Appréciation des risques:",
            "",
            "  a) Identification:",
            "    • Actifs: Données, systèmes, services",
            "    • Menaces: Qui/quoi peut nuire?",
            "    • Vulnérabilités: Faiblesses exploitables",
            "    • Impacts: Conséquences potentielles",
            "",
            "  b) Analyse:",
            "    • Évaluer la vraisemblance (probabilité)",
            "    • Évaluer les conséquences (impact)",
            "    • Niveau de risque = Vraisemblance × Impact",
            "",
            "  c) Évaluation:",
            "    • Comparer risques au critère d'acceptation",
            "    • Prioriser: Critique > Élevé > Moyen > Faible",
            "",
            "3️⃣ Traitement des risques (4 options):",
            "",
            "  🛡️ Réduction (Mitigation):",
            "    • Implémenter des contrôles de sécurité",
            "    • Ex: Firewall, chiffrement, MFA",
            "    • Objectif: Diminuer probabilité ou impact",
            "",
            "  ✅ Acceptation:",
            "    • Accepter le risque résiduel",
            "    • Décision de la direction",
            "    • Documenter formellement",
            "    • Ex: Risque faible, coût de protection > impact",
            "",
            "  🔄 Transfert:",
            "    • Transférer à un tiers",
            "    • Ex: Assurance cyber, externalisation",
            "    • Le risque existe toujours, mais partagé",
            "",
            "  🚫 Évitement:",
            "    • Cesser l'activité à risque",
            "    • Ex: Arrêt d'un service trop vulnérable",
            "    • Rare car impact business important",
            "",
            "4️⃣ Communication:",
            "  • Informer les parties prenantes",
            "  • Reporting à la direction",
            "  • Sensibilisation des équipes",
            "",
            "5️⃣ Surveillance et revue:",
            "  • Monitoring continu des risques",
            "  • Réévaluation périodique (annuelle)",
            "  • Mise à jour après incidents ou changements",
            "  • Nouvelles menaces, nouvelles vulnérabilités"
          ],
          formula: "Gestion continue: Identifier → Analyser → Évaluer → Traiter → Surveiller → Réviser"
        }
      ]
    },
    {
      id: 6,
      title: "Pentesting",
      icon: Bug,
      color: "from-pink-500 to-rose-600",
      sections: [
        {
          id: "pentest-def",
          title: "🎯 Pentesting - Test d'Intrusion",
          content: "Simulation d'attaque informatique autorisée pour identifier les vulnérabilités d'un système avant que de vrais pirates ne les exploitent. Aussi appelé 'Ethical Hacking'.",
          examples: [
            "🎯 Objectifs du pentest:",
            "  • Identifier les failles de sécurité (techniques, humaines, physiques)",
            "  • Évaluer la résilience du SI face aux attaques",
            "  • Tester l'efficacité des contrôles de sécurité",
            "  • Fournir recommandations priorisées",
            "  • Démontrer impact réel d'une compromission",
            "",
            "📊 Types de tests:",
            "",
            "  🏢 Test interne (Inside):",
            "    • Simuler attaquant avec accès réseau interne",
            "    • Scénario: Employé malveillant, poste compromis",
            "    • Cible: Segmentation, escalade de privilèges",
            "",
            "  🌐 Test externe (Outside):",
            "    • Depuis Internet, sans accès préalable",
            "    • Cible: Périmètre exposé, applications web",
            "    • Réaliste: Vision de l'attaquant externe",
            "",
            "  💻 Test d'application web:",
            "    • Focus sur vulnérabilités OWASP Top 10",
            "    • SQLi, XSS, CSRF, broken auth, etc.",
            "",
            "  📱 Test mobile (iOS/Android):",
            "    • Analyse de l'app et de ses communications",
            "    • Reverse engineering, analyse API",
            "",
            "  👤 Ingénierie sociale:",
            "    • Phishing, vishing (appel), SMishing (SMS)",
            "    • Test de la vigilance humaine",
            "    • Tailgating: Suivre quelqu'un pour entrer",
            "",
            "🎭 Approches (niveau de connaissance):",
            "",
            "  ⚫ Black Box (Boîte noire):",
            "    • Aucune information fournie",
            "    • Vision 100% attaquant externe",
            "    • Plus long, plus réaliste",
            "",
            "  ⚪ White Box (Boîte blanche):",
            "    • Connaissance complète: code source, architecture",
            "    • Audit approfondi, détection maximale",
            "    • Plus court, exhaustif",
            "",
            "  🔘 Grey Box (Boîte grise):",
            "    • Informations partielles (utilisateur standard)",
            "    • Équilibre réalisme/efficacité",
            "    • Le plus courant"
          ],
          formula: "Pentest = Attaque simulée + Méthodologie + Rapport détaillé"
        },
        {
          id: "phases",
          title: "🔄 Les 7 Phases du Pentest",
          content: "Méthodologie structurée inspirée du Cyber Kill Chain et PTES (Penetration Testing Execution Standard)",
          examples: [
            "1️⃣ Planification & Cadrage:",
            "  • Définir périmètre (IPs, domaines, applications)",
            "  • Établir règles d'engagement (RoE)",
            "  • Fenêtre de test (horaires autorisés)",
            "  • Contacts d'urgence",
            "  • Accord juridique (contrat, NDA)",
            "",
            "2️⃣ Reconnaissance (OSINT):",
            "  • Passive: Sans toucher la cible",
            "    - Google Dorking: site:example.com filetype:pdf",
            "    - WHOIS: Propriétaire domaine",
            "    - Shodan: Appareils exposés",
            "    - LinkedIn: Employés, organigramme",
            "    - Recherche fuites: HaveIBeenPwned",
            "  • Active: Interaction avec la cible",
            "    - DNS enumeration: sous-domaines",
            "    - Scan réseau léger",
            "",
            "3️⃣ Scanning & Énumération:",
            "  • Nmap: Scan de ports, détection OS/services",
            "  • Vulnérabilité scan: Nessus, OpenVAS",
            "  • Énumération: Utilisateurs, partages SMB",
            "  • Banner grabbing: Versions logiciels",
            "  • Cartographie complète de l'infrastructure",
            "",
            "4️⃣ Exploitation:",
            "  • Exploiter les vulnérabilités identifiées",
            "  • Metasploit: Framework d'exploitation",
            "  • Exploitation manuelle: SQLi, XSS, RCE",
            "  • Obtenir accès initial (foothold)",
            "  • Capture de credentials",
            "",
            "5️⃣ Post-Exploitation & Escalade:",
            "  • Escalade de privilèges: user → admin/root",
            "  • Mouvement latéral: Pivoter vers autres machines",
            "  • Persistence: Backdoor, scheduled task",
            "  • Exfiltration de données sensibles (preuve)",
            "  • Covering tracks: Nettoyer les logs",
            "",
            "6️⃣ Analyse & Rapport:",
            "  • Documenter toutes les vulnérabilités",
            "  • Prioriser: Critique > Élevé > Moyen > Faible",
            "  • Preuves: Screenshots, logs, PoC",
            "  • Rapport exécutif (direction)",
            "  • Rapport technique (équipe IT)",
            "  • Recommandations de remédiation",
            "",
            "7️⃣ Retest (Optionnel):",
            "  • Vérifier que correctifs sont efficaces",
            "  • Généralement 2-4 semaines après remédiation"
          ],
          formula: "Méthodologie: Recon → Scan → Exploit → Post-Exploit → Report"
        },
        {
          id: "outils",
          title: "🛠️ Arsenal du Pentester",
          content: "Suite complète d'outils pour chaque phase du test d'intrusion",
          examples: [
            "🐉 Kali Linux:",
            "  • Distribution Linux spécialisée pentesting",
            "  • 600+ outils préinstallés",
            "  • Basée sur Debian",
            "  • Alternatives: Parrot OS, BlackArch",
            "",
            "🔍 Reconnaissance & OSINT:",
            "  • theHarvester: Emails, sous-domaines",
            "  • Maltego: Cartographie relations",
            "  • Recon-ng: Framework OSINT",
            "  • Shodan: Moteur de recherche IoT",
            "  • Amass: Découverte de sous-domaines",
            "",
            "📡 Scanning & Énumération:",
            "  • Nmap: Scanner réseau (le plus utilisé)",
            "  • Masscan: Scan ultra-rapide de ports",
            "  • Nikto: Scanner vulnérabilités web",
            "  • Nessus/OpenVAS: Scan vulnérabilités complet",
            "  • Enum4linux: Énumération Windows/Samba",
            "",
            "💥 Exploitation:",
            "  • Metasploit Framework: Exploitation + post-exploit",
            "  • SQLmap: Automatisation SQL Injection",
            "  • Exploit-DB: Base de données d'exploits",
            "  • Mimikatz: Extraction credentials Windows",
            "  • Responder: LLMNR/NBT-NS poisoning",
            "",
            "🕸️ Web Application:",
            "  • Burp Suite: Proxy intercepteur, scanner",
            "  • OWASP ZAP: Alternative open-source à Burp",
            "  • ffuf: Fuzzing de répertoires/paramètres",
            "  • Gobuster: Brute force de chemins web",
            "  • wfuzz: Fuzzer web avancé",
            "",
            "🔓 Cracking & Brute Force:",
            "  • Hashcat: Crackage de hash (GPU)",
            "  • John the Ripper: Crackage passwords",
            "  • Hydra: Brute force services (SSH, FTP, HTTP)",
            "  • CeWL: Génération wordlist depuis site web",
            "",
            "📊 Analyse Réseau:",
            "  • Wireshark: Analyseur de paquets (GUI)",
            "  • tcpdump: Capture de paquets (CLI)",
            "  • Ettercap: MITM attack framework",
            "  • Bettercap: Swiss army knife for networks",
            "",
            "🔧 Post-Exploitation:",
            "  • PowerSploit: PowerShell pour post-exploit Windows",
            "  • Empire: Post-exploitation framework",
            "  • BloodHound: Cartographie Active Directory",
            "  • LinPEAS/WinPEAS: Énumération privilège escalation",
            "",
            "📝 Reporting:",
            "  • Dradis: Collaboration et reporting",
            "  • Faraday: Gestion de pentests",
            "  • CherryTree: Prise de notes hiérarchiques"
          ],
          formula: "Pentester = Compétences + Méthodologie + Outils adaptés"
        }
      ]
    },
    {
      id: 7,
      title: "Correction Examen",
      icon: CheckCircle,
      color: "from-green-500 to-emerald-600",
      sections: [
        {
          id: "ex1",
          title: "📝 Exercice 1: Gestion des Risques ISO 27001 (6pts)",
          content: "Appréciation et traitement des risques pour IT Solutions",
          examples: [
            "1. Appréciation des risques (3pts):",
            "• Identification des actifs: Données clients, codes sources, serveurs",
            "• Identification des menaces: Cyberattaques, fuites, malwares",
            "• Identification des vulnérabilités: Systèmes non patchés, mots de passe faibles",
            "• Évaluation de l'impact: Financier, réputation, légal (RGPD)",
            "• Estimation de la probabilité: Analyser la fréquence",
            "• Calcul: Risque = Impact × Probabilité",
            "",
            "2. Traitement des risques (3pts):",
            "• Réduction: Firewall, antivirus, chiffrement, formation",
            "• Transfert: Assurance cyber-risques",
            "• Acceptation: Documenter les risques mineurs",
            "• Évitement: Cesser les activités trop risquées"
          ]
        },
        {
          id: "ex2-phases",
          title: "🎯 Exercice 2: Phases d'Attaque (8pts)",
          content: "Analyse des 7 phases d'une cyberattaque",
          examples: [
            "Phase 1 - Reconnaissance:",
            "• Action: Scan de ports, recherche d'infos utilisateurs",
            "• Prévention: Masquer services, limiter réponses",
            "• Détection: IDS/IPS, surveillance des scans",
            "",
            "Phase 2 - Armement/Préparation:",
            "• Action: Test des vulnérabilités",
            "• Prévention: Gestion correctifs, audits",
            "• Détection: Analyse tentatives d'exploitation",
            "",
            "Phase 3 - Livraison:",
            "• Action: Trafic inhabituel depuis IP étrangère",
            "• Prévention: Filtrage IP, WAF",
            "• Détection: Monitoring trafic réseau"
          ]
        },
        {
          id: "ex2-exploit",
          title: "💥 Phases 4-7: Exploitation & Actions",
          content: "Suite de l'analyse des phases d'attaque",
          examples: [
            "Phase 4 - Exploitation:",
            "• Action: Injection SQL, exploitation vulnérabilités",
            "• Prévention: Validation entrées, requêtes préparées, WAF",
            "• Détection: Anomalies dans logs applicatifs",
            "",
            "Phase 5 - Installation:",
            "• Action: Scripts malveillants, connexion persistante",
            "• Prévention: Antimalware, moindre privilège",
            "• Détection: EDR, analyse comportementale",
            "",
            "Phase 6 - Command & Control (C2):",
            "• Action: Connexion persistante avec IP compromise",
            "• Prévention: Segmentation réseau, blocage IPs",
            "• Détection: Analyse trafic sortant, beaconing",
            "",
            "Phase 7 - Actions sur Objectifs:",
            "• Action: Mouvement latéral, exfiltration, modification logs",
            "• Prévention: DLP, MFA, segmentation",
            "• Détection: SIEM, corrélation événements"
          ]
        },
        {
          id: "ex3-kerberos",
          title: "🔐 Exercice 3: Authentification Kerberos (6pts)",
          content: "Protocole d'authentification sécurisé",
          examples: [
            "1. Échanges de clés (1pt):",
            "• Chaque utilisateur: clé secrète (mot de passe)",
            "• KDC connaît toutes les clés utilisateurs",
            "• Chaque serveur: clé partagée avec KDC",
            "• Distribution initiale sécurisée hors bande",
            "",
            "2. Structure des Tickets (1.5pts):",
            "TGT contient: identité, clé session TGS, validité",
            "Ticket Service contient: identité, clé session, service",
            "",
            "3. Protection contre rejeu (1.5pts):",
            "• Horodatage: rejette requêtes anciennes",
            "• Durée limitée: tickets expirent",
            "• Nonces: numéros uniques",
            "• Authenticators: messages uniques + timestamp",
            "• Cache: serveur garde authenticators récents"
          ]
        },
        {
          id: "ex3-tgs",
          title: "🎫 Kerberos: TGS & Extensions",
          content: "Utilité du TGS et améliorations possibles",
          examples: [
            "4. Utilité du TGS (1pt):",
            "• Séparation des rôles: AS authentifie 1 fois",
            "• Réduction de charge sur AS",
            "• Sécurité renforcée: limite exposition clé",
            "• Scalabilité: accès multi-services sans ré-auth",
            "• SSO: Single Sign-On",
            "",
            "5. Extensions possibles (1pt):",
            "• Chiffrement renforcé: AES-256 vs DES",
            "• Authentification mutuelle obligatoire",
            "• Support PKINIT: certificats + clés publiques",
            "• MFA: second facteur au TGT",
            "• Tokens révocables avant expiration",
            "• Cross-realm amélioré: confiance inter-domaines"
          ]
        }
      ]
    }
  ];

  const activeChapterData = chapters.find(ch => ch.id === activeChapter);
  const Icon = activeChapterData.icon;

  return (
    <div className="min-h-screen bg-black text-gray-100 relative overflow-hidden">
      {/* Animated Background Grid */}
      <div className="absolute inset-0 opacity-20">
        <div className="absolute inset-0" style={{
          backgroundImage: `linear-gradient(#00ff41 1px, transparent 1px), linear-gradient(90deg, #00ff41 1px, transparent 1px)`,
          backgroundSize: '50px 50px',
          animation: 'grid-move 20s linear infinite'
        }}></div>
      </div>

      {/* Glowing Orbs */}
      <div className="absolute top-20 left-20 w-96 h-96 bg-cyan-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
      <div className="absolute bottom-20 right-20 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse delay-1000"></div>

      <div className="relative max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="text-center mb-12 pt-8">
          <div className="flex items-center justify-center gap-4 mb-4">
            <Terminal className="w-12 h-12 text-cyan-400 animate-pulse" />
            <h1 className="text-5xl font-black bg-gradient-to-r from-cyan-400 via-green-400 to-cyan-400 bg-clip-text text-transparent">
              CYBERSECURITY STUDY GUIDE
            </h1>
            <Fingerprint className="w-12 h-12 text-green-400 animate-pulse" />
          </div>
          <p className="text-xl text-gray-400 font-mono tracking-wider">
            &gt; Preparation D'exam 
          </p>
          <div className="mt-4 inline-block px-6 py-2 bg-gradient-to-r from-cyan-500/20 to-green-500/20 border border-cyan-500/50 rounded-full">
            <span className="text-cyan-400 font-mono text-sm">STATUS: OPERATIONAL</span>
          </div>
        </div>

        {/* Chapter Navigation */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-12">
          {chapters.map((chapter) => {
            const ChapterIcon = chapter.icon;
            const isActive = activeChapter === chapter.id;
            return (
              <button
                key={chapter.id}
                onClick={() => setActiveChapter(chapter.id)}
                className={`group relative p-6 rounded-xl transition-all duration-300 transform hover:scale-105 ${
                  isActive
                    ? 'bg-gradient-to-br ' + chapter.color + ' shadow-2xl shadow-cyan-500/50'
                    : 'bg-gray-900 border border-gray-800 hover:border-cyan-500/50'
                }`}
              >
                <div className="relative z-10">
                  <ChapterIcon className={`w-8 h-8 mx-auto mb-3 ${isActive ? 'text-white' : 'text-gray-400 group-hover:text-cyan-400'} transition-colors`} />
                  <div className={`text-xs font-bold text-center mb-1 font-mono ${isActive ? 'text-white' : 'text-gray-500'}`}>
                    [CH.{chapter.id}]
                  </div>
                  <div className={`text-xs text-center font-semibold ${isActive ? 'text-white' : 'text-gray-400'}`}>
                    {chapter.title}
                  </div>
                </div>
                {isActive && (
                  <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/20 to-transparent rounded-xl animate-pulse"></div>
                )}
              </button>
            );
          })}
        </div>

        {/* Chapter Content */}
        <div className="relative bg-gray-900/80 backdrop-blur-xl rounded-2xl border border-cyan-500/30 shadow-2xl shadow-cyan-500/20 overflow-hidden">
          {/* Header Glow */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-green-500 to-cyan-500 animate-pulse"></div>
          
          <div className="p-8">
            <div className="flex items-center gap-4 mb-8 pb-6 border-b border-gray-800">
              <div className={`p-4 rounded-xl bg-gradient-to-br ${activeChapterData.color} shadow-lg`}>
                <Icon className="w-10 h-10 text-white" />
              </div>
              <div className="flex-1">
                <div className="text-sm font-mono text-cyan-400 mb-1">[CHAPTER_{activeChapterData.id}]</div>
                <h2 className="text-3xl font-black text-white">
                  {activeChapterData.title}
                </h2>
              </div>
              <div className="text-right">
                <div className="text-xs font-mono text-gray-500">SECTIONS</div>
                <div className="text-2xl font-bold text-cyan-400">{activeChapterData.sections.length}</div>
              </div>
            </div>

            {/* Sections */}
            <div className="space-y-4">
              {activeChapterData.sections.map((section, idx) => (
                <div
                  key={section.id}
                  className="group relative bg-gray-800/50 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-all overflow-hidden"
                >
                  <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-cyan-500 to-green-500 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  
                  <button
                    onClick={() => toggleSection(section.id)}
                    className="w-full p-5 text-left flex items-center justify-between hover:bg-gray-800/80 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div className="text-xs font-mono text-gray-600">
                        {String(idx + 1).padStart(2, '0')}
                      </div>
                      <span className="text-lg font-bold text-white">
                        {section.title}
                      </span>
                    </div>
                    <div className={`text-2xl transition-transform ${expandedSections[section.id] ? 'rotate-45 text-cyan-400' : 'text-gray-600'}`}>
                      +
                    </div>
                  </button>
                  
                  {expandedSections[section.id] && (
                    <div className="px-5 pb-5 space-y-4 animate-fadeIn">
                      {/* Description */}
                      <div className="bg-gradient-to-br from-gray-900/90 to-gray-800/90 border-l-4 border-cyan-500 rounded-lg p-5 shadow-lg">
                        <div className="text-xs font-mono text-cyan-400 mb-3 uppercase tracking-wider flex items-center gap-2">
                          <div className="w-1 h-1 bg-cyan-400 rounded-full"></div>
                          Description
                        </div>
                        <p className="text-gray-200 leading-relaxed text-base">
                          {section.content}
                        </p>
                      </div>
                      
                      {section.formula && (
                        <div className="bg-gradient-to-r from-cyan-500/10 to-green-500/10 border-l-4 border-green-500 rounded-lg p-5 shadow-lg">
                          <div className="flex items-center gap-2 mb-3">
                            <Cpu className="w-4 h-4 text-green-400" />
                            <div className="text-xs font-mono text-green-400 uppercase tracking-wider">Formule Clé</div>
                          </div>
                          <div className="text-green-300 font-mono text-sm bg-black/40 p-4 rounded border border-green-500/30 shadow-inner">
                            {section.formula}
                          </div>
                        </div>
                      )}
                      
                      {/* Exemples */}
                      <div className="space-y-3">
                        <div className="text-xs font-mono text-gray-400 mb-4 uppercase tracking-wider flex items-center gap-2">
                          <div className="w-1 h-1 bg-gray-400 rounded-full"></div>
                          Détails & Exemples Pratiques
                        </div>
                        <div className="space-y-2">
                          {section.examples.map((example, idx) => {
                            // Déterminer si c'est un titre principal (se termine par ":" et pas d'indentation)
                            const isMainTitle = example.trim().endsWith(':') && !example.startsWith('  ');
                            // Déterminer si c'est un sous-élément (commence par "  •" ou "  -" ou simple indentation)
                            const isSubItem = example.startsWith('  •') || example.startsWith('  -') || (example.startsWith('  ') && !example.trim().endsWith(':'));
                            // Ligne vide
                            const isEmpty = example.trim() === '';
                            
                            if (isEmpty) {
                              return <div key={idx} className="h-2"></div>;
                            }
                            
                            if (isMainTitle) {
                              return (
                                <div key={idx} className="mt-4 mb-2">
                                  <div className="flex items-center gap-3 bg-gradient-to-r from-cyan-500/20 to-transparent border-l-3 border-cyan-500 px-4 py-3 rounded-r">
                                    <div className="text-cyan-400 font-bold text-base">
                                      {example.trim()}
                                    </div>
                                  </div>
                                </div>
                              );
                            }
                            
                            if (isSubItem) {
                              return (
                                <div key={idx} className="ml-6 flex items-start gap-3 py-1.5">
                                  <div className="text-cyan-400/60 font-mono text-xs mt-0.5">•</div>
                                  <div className="text-gray-300 text-sm leading-relaxed">
                                    {example.trim().replace(/^[•\-]\s*/, '')}
                                  </div>
                                </div>
                              );
                            }
                            
                            // Élément normal
                            return (
                              <div
                                key={idx}
                                className="bg-gray-800/60 border border-gray-700/50 hover:border-cyan-500/40 rounded-lg p-4 transition-all duration-200 hover:bg-gray-800/80 hover:shadow-lg hover:shadow-cyan-500/10"
                              >
                                <div className="flex items-start gap-3">
                                  <div className="text-cyan-400 font-mono text-xs mt-1 opacity-70">▸</div>
                                  <div className="text-gray-200 text-sm flex-1 leading-relaxed whitespace-pre-line">
                                    {example}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Quick Reference Cards */}
        <div className="mt-8 grid md:grid-cols-3 gap-6">
          <div className="group relative bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-6 hover:shadow-xl hover:shadow-green-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-green-500/20 rounded-full blur-2xl"></div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <div className="text-green-400 font-bold font-mono text-sm">FORMULE_RISQUE</div>
              </div>
              <div className="text-green-300 font-mono text-sm bg-black/30 p-3 rounded border border-green-500/20">
                R = M × V / CM
              </div>
            </div>
          </div>
          
          <div className="group relative bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border border-blue-500/30 rounded-xl p-6 hover:shadow-xl hover:shadow-blue-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-blue-500/20 rounded-full blur-2xl"></div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-3">
                <Lock className="w-5 h-5 text-blue-400" />
                <div className="text-blue-400 font-bold font-mono text-sm">PILIERS_CANDI</div>
              </div>
              <div className="text-blue-300 text-xs leading-relaxed">
                <span className="text-cyan-400">C</span>onfidentialité + 
                <span className="text-cyan-400">A</span>uthentification + 
                <span className="text-cyan-400">N</span>on-répudiation + 
                <span className="text-cyan-400">D</span>isponibilité + 
                <span className="text-cyan-400">I</span>ntégrité
              </div>
            </div>
          </div>
          
          <div className="group relative bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-6 hover:shadow-xl hover:shadow-purple-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-purple-500/20 rounded-full blur-2xl"></div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-3">
                <Network className="w-5 h-5 text-purple-400" />
                <div className="text-purple-400 font-bold font-mono text-sm">ARCHITECTURE_PKI</div>
              </div>
              <div className="text-purple-300 text-xs leading-relaxed">
                CA + RA + CRL + Repository = Trust System
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center">
          <p className="text-gray-600 font-mono text-xs">
            [SYSTÈME_ACTIVÉ] • VERSION_2026 • SÉCURITÉ_MAXIMALE
          </p>
        </div>

        <div className="mt-12 pt-6 border-t border-gray-800/20">
          <div className="text-center space-y-2">
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">
              [DEVELOPED BY] MOHAMED AZZAM
            </p>
            <p className="text-xs font-mono text-gray-400">
              © 2026 • SECURITY_STUDY_GUIDE
            </p>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes grid-move {
          0% { transform: translate(0, 0); }
          100% { transform: translate(50px, 50px); }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fadeIn {
          animation: fadeIn 0.3s ease-out;
        }
      `}</style>
    </div>
  );
};

export default SecurityStudyGuide;