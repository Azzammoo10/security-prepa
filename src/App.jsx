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
          title: "👹 Menace (تهديد - tahdi) = Exploitation",
          content: "Agent (personne, logiciel, événement) qui cherche à exploiter (يستغل) une vulnérabilité pour nuire (يضر - ydar) au système",
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
          content: "Un tableau simple pour savoir quels risques traiter en premier",
          examples: [
            "🎯 C'est quoi?",
            "  • Un tableau qui croise 2 choses:",
            "  • Horizontal (X): À quelle fréquence ça peut arriver?",
            "  • Vertical (Y): Si ça arrive, c'est grave comment?",
            "",
            "📏 L'échelle de 1 à 5:",
            "",
            "Probabilité (combien de fois?):",
            "  1 = Presque jamais (1 fois tous les 10 ans)",
            "  2 = Rarement (1 fois tous les 5 ans)",
            "  3 = Parfois (1 fois par an)",
            "  4 = Souvent (plusieurs fois par an)",
            "  5 = Très souvent (tous les mois)",
            "",
            "Impact (c'est grave?):",
            "  1 = Pas grave (petit bug, vite réglé)",
            "  2 = Moyen (quelques heures perdues)",
            "  3 = Embêtant (journée de travail perdue)",
            "  4 = Grave (perte d'argent, clients mécontents)",
            "  5 = Catastrophe (fermeture entreprise possible)",
            "",
            "🎨 Les couleurs:",
            "",
            "🟢 VERT (1-4): Tranquille",
            "  • C'est pas grave OU ça arrive jamais",
            "  • Exemple: Bug d'affichage rare",
            "  • Action: On surveille, c'est tout",
            "",
            "🟡 JAUNE (5-12): Attention",
            "  • Commence à être embêtant",
            "  • Exemple: Panne serveur 1 fois/an",
            "  • Action: On prévoit une solution",
            "",
            "🟠 ORANGE (13-19): Urgent",
            "  • Faut s'en occuper vite!",
            "  • Exemple: Backup qui marche pas bien",
            "  • Action: On met un plan en place",
            "",
            "🔴 ROUGE (20-25): ALERTE!",
            "  • Danger maximum! À traiter MAINTENANT",
            "  • Exemple: Pas d'antivirus + site web public",
            "  • Action: Tout arrêter jusqu'à correction",
            "",
            "💡 Exemples concrets:",
            "",
            "Email de phishing:",
            "  • Probabilité: 4 (arrive souvent)",
            "  • Impact: 5 (peut voler toutes les données)",
            "  • Score: 4 × 5 = 20 → 🔴 ROUGE (URGENT!)",
            "",
            "Souris qui marche mal:",
            "  • Probabilité: 2 (rarement)",
            "  • Impact: 1 (juste changer la souris)",
            "  • Score: 2 × 1 = 2 → 🟢 VERT (pas grave)",
            "",
            "Serveur qui plante:",
            "  • Probabilité: 3 (1 fois par an)",
            "  • Impact: 4 (clients bloqués)",
            "  • Score: 3 × 4 = 12 → 🟡 JAUNE (à prévoir)",
            "",
            "🎯 Comment l'utiliser?",
            "  1. Liste tous tes risques",
            "  2. Pour chacun, demande: \"Ça arrive souvent?\" (1-5)",
            "  3. Puis: \"C'est grave?\" (1-5)",
            "  4. Multiplie les 2 chiffres",
            "  5. Traite d'abord les rouges, puis oranges, puis jaunes"
          ],
          formula: "Score = Fréquence × Gravité | Rouge (≥20) = URGENT | Orange (13-19) = Vite | Jaune (5-12) = Bientôt"
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
        },
        {
          id: "kerberos",
          title: "🎫 Kerberos - Authentification",
          content: "Système d'authentification qui permet de vérifier ton identité sans envoyer ton mot de passe sur le réseau",
          examples: [
            "🎯 C'est quoi Kerberos?",
            "  • Comme un guichet qui te donne des tickets",
            "  • Tu montres ton ticket au lieu de ton mot de passe",
            "  • Les tickets expirent après un temps",
            "",
            "👥 Les acteurs:",
            "  • Toi (Client): Alice qui veut accéder à un service",
            "  • KDC (Key Distribution Center): Le guichet qui donne les tickets",
            "  • Serveur: Le service que tu veux utiliser (email, fichiers...)",
            "",
            "🎫 Les 3 étapes simples:",
            "",
            "1️⃣ Demander le TGT (Ticket d'entrée):",
            "  • Tu tapes ton mot de passe",
            "  • KDC vérifie et te donne un TGT",
            "  • TGT valable 10h environ",
            "  • C'est comme un bracelet d'entrée à une fête",
            "",
            "2️⃣ Demander un Ticket de Service:",
            "  • Tu montres ton TGT au KDC",
            "  • Tu dis quel service tu veux (email, fichier...)",
            "  • KDC te donne un ticket pour CE service",
            "  • Ticket valable 5-10 minutes",
            "",
            "3️⃣ Accéder au service:",
            "  • Tu donnes le ticket au serveur",
            "  • Serveur vérifie le ticket",
            "  • Tu peux utiliser le service",
            "  • Pas besoin de retaper le mot de passe!",
            "",
            "🔐 Sécurité:",
            "  • Mot de passe jamais envoyé sur réseau",
            "  • Tickets chiffrés (impossible à lire)",
            "  • Tickets avec date d'expiration",
            "  • Si quelqu'un vole ticket → inutile après expiration",
            "",
            "✅ Avantages:",
            "  • SSO (Single Sign-On): 1 seul mot de passe pour tous les services",
            "  • Sécurisé: Pas de mot de passe qui circule",
            "  • Pratique: Plus besoin de se reconnecter sans arrêt",
            "",
            "💡 Exemple concret:",
            "  • 8h: Alice se connecte → reçoit TGT",
            "  • 9h: Veut ses emails → demande ticket Email",
            "  • 10h: Veut un fichier → demande ticket Fichiers",
            "  • 12h: TGT encore valide, pas besoin de mot de passe!",
            "  • 18h: TGT expire → doit se reconnecter demain"
          ],
          formula: "1 mot de passe → TGT (10h) → Tickets services (10min) → Accès sans redemander password"
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
          id: "demarche",
          title: "🎯 Démarche de Gestion des Risques",
          content: "Une démarche typique de la gestion des risques peut se baser sur EBIOS et la famille ISO 27000",
          examples: [
            "📊 Approche structurée:",
            "  • Méthodologie EBIOS pour l'analyse",
            "  • Normes ISO 27000 pour le cadre",
            "  • Complémentarité des deux approches"
          ],
          formula: "Gestion des risques = EBIOS (Méthode) + ISO 27000 (Normes)"
        },
        {
          id: "ebios",
          title: "📋 EBIOS - Méthodologie",
          content: "EBIOS (Expression des Besoins et Identification des Objectifs de Sécurité) est une méthodologie d'analyse et de gestion des risques utilisée pour protéger les systèmes d'information",
          examples: [
            "🎯 Objectifs principaux:",
            "  • Identifier les menaces, vulnérabilités et risques",
            "  • Évaluer les impacts sur l'organisation",
            "  • Définir des mesures de sécurité adaptées",
            "",
            "📖 Modules EBIOS:",
            "",
            "1️⃣ Analyse du contexte (périmètres):",
            "  • Définir le périmètre du système étudié",
            "  • Identifier les actifs et parties prenantes",
            "  • Établir le contexte de l'analyse",
            "",
            "2️⃣ Étude des événements redoutés:",
            "  • Identifier les événements à impact négatif",
            "  • Évaluer leur gravité",
            "  • Définir les biens essentiels à protéger",
            "",
            "3️⃣ Analyse des scénarios de menace:",
            "  • Construire les chemins d'attaque",
            "  • Identifier les sources de risques",
            "  • Évaluer les modes opératoires",
            "",
            "4️⃣ Évaluation des risques:",
            "  • Mesurer le niveau de risque",
            "  • Prioriser selon gravité × vraisemblance",
            "  • Cartographier les risques identifiés",
            "",
            "5️⃣ Traitement des risques:",
            "  • 🛡️ Réduction: Mesures de sécurité",
            "  • ✅ Acceptation: Risque assumé",
            "  • 🔄 Transfert: Assurance, externalisation"
          ],
          formula: "Risque = Gravité × Vraisemblance | Traitement: Réduire / Accepter / Transférer"
        },
        {
          id: "iso27001",
          title: "🏅 ISO 27001 - SMSI",
          content: "ISO 27001 définit les exigences pour mettre en place un SMSI (Système de Management de la Sécurité de l'Information)",
          examples: [
            "🔄 Basé sur le cycle PDCA:",
            "",
            "PLAN (Planifier):",
            "  • Établir le contexte et la politique de sécurité",
            "  • Analyser les risques",
            "  • Définir les objectifs de sécurité",
            "",
            "DO (Faire):",
            "  • Mettre en œuvre les mesures de sécurité",
            "  • Déployer les contrôles",
            "  • Former les équipes",
            "",
            "CHECK (Vérifier):",
            "  • Surveiller et mesurer l'efficacité",
            "  • Audits internes",
            "  • Revues de direction",
            "",
            "ACT (Agir):",,
            "  • Actions correctives",
            "  • Amélioration continue",
            "  • Adaptation aux changements",
            "",
            "🎯 Objectifs du SMSI:",
            "  • Protéger la CONFIDENTIALITÉ",
            "  • Garantir l'INTÉGRITÉ",
            "  • Assurer la DISPONIBILITÉ des informations",
            "",
            "📋 Approche par les risques:",
            "  • Identification des actifs",
            "  • Évaluation des menaces",
            "  • Sélection des contrôles appropriés"
          ],
          formula: "SMSI = PDCA + Approche risques → Protège Confidentialité, Intégrité, Disponibilité"
        },
        {
          id: "iso27005",
          title: "📊 ISO 27005 - Gestion des Risques",
          content: "ISO 27005 est dédiée à la gestion des risques liés à la sécurité de l'information",
          examples: [
            "🔗 Relation avec ISO 27001:",
            "  • Complète ISO 27001",
            "  • Fournit la méthodologie détaillée",
            "  • Guide pour l'appréciation des risques",
            "",
            "📋 Méthode structurée en 4 étapes:",
            "  1️⃣ Identifier les risques",
            "  2️⃣ Analyser les risques",
            "  3️⃣ Évaluer les risques",
            "  4️⃣ Traiter les risques",
            "",
            "✅ Compatible avec EBIOS:",
            "  • Même philosophie de gestion des risques",
            "  • Aide à décider quels risques accepter ou réduire",
            "  • Approche complémentaire et cohérente"
          ],
          formula: "ISO 27005: Identifier → Analyser → Évaluer → Traiter (compatible EBIOS)"
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
          id: "definition",
          title: "🎯 C'est quoi le Pentesting?",
          content: "Pentesting = Simuler des attaques réelles afin d'évaluer le niveau de sécurité des systèmes d'information et d'identifier les vulnérabilités avant qu'elles ne soient exploitées par des attaquants",
          examples: [
            "💡 Analogie simple:",
            "  • B7al ila jiti t7ell bab dyal dar dyalek bach tchouf wach sahl ytsra9",
            "  • Kanqelbou 3la lmochkil 9bel ma chi hacker yl9ah",
            "",
            "🎯 Objectif principal:",
            "  • Trouver les failles AVANT les vrais hackers",
            "  • Tester la sécurité du système",
            "  • Donner des recommandations pour corriger"
          ],
          formula: "Pentest = Attaque simulée (légale) + Identification failles + Rapport solutions"
        },
        {
          id: "types",
          title: "📊 Types de Pentesting",
          content: "Classification selon l'origine de l'attaque et la cible",
          examples: [
            "🏢 Test INTERNE (Inside):",
            "  • Attaque men dakhil charika",
            "  • Scénario: Employé malveillant ou poste compromis",
            "  • Exemple: PC d'un employé hacké, qu'est-ce qu'il peut faire?",
            "  • Objectif: Tester la segmentation réseau interne",
            "",
            "🌐 Test EXTERNE (Outside):",
            "  • Attaque men barra (depuis Internet)",
            "  • Sans accès préalable au réseau",
            "  • Exemple: Hacker qui essaie d'entrer depuis chez lui",
            "  • Objectif: Tester le périmètre exposé (firewall, VPN...)",
            "",
            "💻 Test WEB (Applications):",
            "  • Test dyal site web o applications",
            "  • Nchoufou wach login wala base de données fihom mouchkil",
            "  • Exemple: SQL Injection, XSS, problèmes d'authentification",
            "  • Focus: OWASP Top 10 (les 10 vulnérabilités les plus courantes)",
            "",
            "👤 Ingénierie Sociale (Social Engineering):",
            "  • Manipuler nass bach yakhdo infos",
            "  • Email kaygoul 'ana l'admin' bach yakhod password",
            "  • Exemple: Phishing, appel téléphonique pour voler credentials",
            "  • But: Tester la vigilance des utilisateurs"
          ],
          formula: "Types: Interne | Externe | Web | Social Engineering"
        },
        {
          id: "phases",
          title: "🔄 Les 6 Phases du Pentest",
          content: "Méthodologie structurée pour mener un test d'intrusion efficace",
          examples: [
            "1️⃣ PLANIFICATION:",
            "  • Définir les objectifs du test",
            "  • Établir le périmètre (quoi tester?)",
            "  • Accord juridique (autorisation écrite)",
            "  • Exemple: Tester uniquement le site web, pas le réseau interne",
            "",
            "2️⃣ RECONNAISSANCE:",
            "  • Collecter des informations sur la cible",
            "  • Google, réseaux sociaux, WHOIS, Shodan",
            "  • Exemple: Trouver les emails des employés sur LinkedIn",
            "  • But: Connaître le système avant de l'attaquer",
            "",
            "3️⃣ SCAN (Analyse):",
            "  • Identifier les vulnérabilités techniques",
            "  • Scanner les ports ouverts (Nmap)",
            "  • Détecter les versions de logiciels",
            "  • Exemple: Port 22 (SSH) ouvert, version 7.4 (vulnérable)",
            "",
            "4️⃣ EXPLOITATION:",
            "  • Exploiter les failles pour accéder au système",
            "  • Utiliser Metasploit, SQLmap, Burp Suite",
            "  • Exemple: Exploitation d'une SQL Injection pour voler la BD",
            "  • Objectif: Prouver que la faille est exploitable",
            "",
            "5️⃣ MAINTIEN (Post-Exploitation):",
            "  • Tester la capacité à rester dans le système sans être détecté",
            "  • Installer backdoor, escalade de privilèges",
            "  • Exemple: User normal → Admin root",
            "  • But: Voir jusqu'où on peut aller",
            "",
            "6️⃣ RAPPORT:",
            "  • Rédiger un rapport avec les résultats et les solutions",
            "  • Prioriser: Critique > Élevé > Moyen > Faible",
            "  • Screenshots, preuves, recommandations",
            "  • Exemple: Vulnérabilité SQL Injection (Critique) → Utiliser requêtes préparées"
          ],
          formula: "Phases: Planification → Reconnaissance → Scan → Exploitation → Maintien → Rapport"
        },
        {
          id: "outils",
          title: "🛠️ Outils du Pentester",
          content: "Arsenal d'outils pour chaque phase du pentesting",
          examples: [
            "🐉 KALI LINUX:",
            "  • Distribution Linux spécialisée pour le pentesting",
            "  • 600+ outils préinstallés",
            "  • Gratuit et open-source",
            "  • L'outil de base de tout pentester",
            "",
            "📡 NMAP (Scanner de réseau):",
            "  • Scanner les ports ouverts",
            "  • Détecter OS et services",
            "  • Exemple: nmap -sV 192.168.1.1",
            "  • Usage: Phase Reconnaissance et Scan",
            "",
            "💥 METASPLOIT (Exploitation):",
            "  • Framework d'exploitation des vulnérabilités",
            "  • Base de données d'exploits",
            "  • Exemple: exploit/windows/smb/ms17_010 (EternalBlue)",
            "  • Usage: Phase Exploitation",
            "",
            "🕸️ BURP SUITE (Sécurité Web):",
            "  • Proxy intercepteur pour applications web",
            "  • Tester SQL Injection, XSS, CSRF",
            "  • Exemple: Intercepter requête login pour tester injection",
            "  • Usage: Test d'applications web",
            "",
            "📊 WIRESHARK (Analyse réseau):",
            "  • Analyse du trafic réseau (sniffer)",
            "  • Capturer les paquets réseau",
            "  • Exemple: Voir les mots de passe en clair (HTTP)",
            "  • Usage: Analyse et détection",
            "",
            "🔓 Autres outils importants:",
            "  • SQLmap: Automatisation SQL Injection",
            "  • Hydra: Brute force de mots de passe",
            "  • John the Ripper: Crackage de hash",
            "  • Nikto: Scanner vulnérabilités web",
            "  • Aircrack-ng: Test sécurité WiFi"
          ],
          formula: "Outils essentiels: Kali Linux + Nmap + Metasploit + Burp Suite + Wireshark"
        },
        {
          id: "exemples",
          title: "💡 Exemples Pratiques",
          content: "Scénarios concrets de pentesting",
          examples: [
            "🎯 Exemple 1: Test d'application web",
            "  1. Reconnaissance: Identifier le site (example.com)",
            "  2. Scan: Nikto scan → Trouve formulaire login",
            "  3. Test SQL Injection: ' OR 1=1 -- dans le champ login",
            "  4. Résultat: Bypass de l'authentification ✓",
            "  5. Rapport: Vulnérabilité CRITIQUE - Utiliser requêtes préparées",
            "",
            "🎯 Exemple 2: Test réseau interne",
            "  1. Connexion: Accès au réseau d'entreprise",
            "  2. Scan Nmap: nmap -sV 192.168.1.0/24",
            "  3. Découverte: Port 445 SMB ouvert (vulnérable MS17-010)",
            "  4. Exploitation: Metasploit + EternalBlue → Accès admin",
            "  5. Rapport: Vulnérabilité CRITIQUE - Patcher Windows immédiatement",
            "",
            "🎯 Exemple 3: Ingénierie sociale",
            "  1. Préparation: Créer faux email 'admin@company.com'",
            "  2. Phishing: 'Votre compte sera bloqué, cliquez ici'",
            "  3. Résultat: 30% des employés cliquent et donnent password",
            "  4. Rapport: Besoin de formation de sensibilisation",
            "",
            "🎯 Exemple 4: Test WiFi",
            "  1. Scan: Aircrack-ng pour détecter réseaux",
            "  2. Capture: Capturer handshake WPA2",
            "  3. Crack: Dictionnaire attack avec wordlist",
            "  4. Résultat: Password faible trouvé en 10 minutes",
            "  5. Rapport: Utiliser WPA3 + mot de passe complexe"
          ],
          formula: "Pentest réel = Méthodologie + Outils + Créativité + Documentation"
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
          id: "contexte",
          title: "📋 Info Examen",
          content: "Session 2023-2024 | Durée: 2H | Sans documents | Total: 20pts",
          examples: [
            "Ex1: ISO 27001 (6pts) | Ex2: Phases Attaque (8pts) | Ex3: Kerberos (6pts)"
          ],
          formula: "3 exercices = 20 points"
        },
        {
          id: "ex1",
          title: "📝 Ex1: ISO 27001 - IT Solutions (6pts)",
          content: "Entreprise IT Solutions: gérer les risques",
          examples: [
            "✅ Analyse des risques (3pts):",
            "",
            "1. Qu'est-ce qu'on a?",
            "   • Données clients, codes, serveurs",
            "",
            "2. Quels dangers?",
            "   • Hackers, employés méchants, fuites",
            "",
            "3. Quelles failles?",
            "   • Logiciels vieux, mots de passe faibles",
            "",
            "4. Si ça arrive?",
            "   • Perte d'argent + clients + procès",
            "",
            "5. Ça peut arriver?",
            "   • Regarder historique",
            "",
            "6. Risque final:",
            "   • Critique / Élevé / Moyen / Faible",
            "",
            "✅ Comment traiter? (3pts):",
            "",
            "• Réduire: Firewall + antivirus + former équipe",
            "• Transférer: Assurance",
            "• Accepter: Si petit risque",
            "• Éviter: Arrêter si trop dangereux"
          ],
          formula: "Risque = Dégâts × Chance"
        },
        {
          id: "ex2",
          title: "🔍 Ex2: Attaque ABC Corp (8pts)",
          content: "7 étapes de l'attaque + comment se protéger",
          examples: [
            "1️⃣ Reconnaissance = chercher info",
            "• Attaque: Scan ports, trouver utilisateurs",
            "• Protection: Cacher infos, bloquer scans",
            "• Détection: IDS voit les scans",
            "",
            "2️⃣ Armement = préparer l'attaque",
            "• Attaque: Tester les failles",
            "• Protection: Mettre à jour logiciels",
            "• Détection: Voir tentatives",
            "",
            "3️⃣ Livraison = envoyer le piège",
            "• Attaque: Trafic suspect d'IP étrangère",
            "• Protection: Bloquer IPs, WAF",
            "• Détection: Surveiller réseau",
            "",
            "4️⃣ Exploitation = entrer dans système",
            "• Attaque: SQL Injection sur base données",
            "• Protection: Valider entrées, WAF",
            "• Détection: Logs bizarres",
            "",
            "5️⃣ Installation = installer porte cachée",
            "• Attaque: Scripts malveillants",
            "• Protection: Antimalware",
            "• Détection: Analyse comportement",
            "",
            "6️⃣ Contrôle = rester connecté",
            "• Attaque: Connexion persistante",
            "• Protection: Segmenter réseau",
            "• Détection: Surveiller trafic sortant",
            "",
            "7️⃣ Objectifs = voler données",
            "• Attaque: Bouger dans réseau, voler data",
            "• Protection: Bloquer copie (DLP)",
            "• Détection: SIEM + alertes volumes"
          ],
          formula: "Chercher → Préparer → Livrer → Entrer → Installer → Contrôler → Voler"
        },
        {
          id: "ex3",
          title: "🔐 Ex3: Kerberos (6pts)",
          content: "Alice veut accéder au serveur S",
          examples: [
            "❓ Q1: Les clés (1pt)",
            "• Alice/Bob: chacun a son code secret",
            "• KDC: a tous les codes",
            "• Serveur S: code partagé avec KDC",
            "",
            "❓ Q2: Dans le ticket? (1.5pts)",
            "TGT: Qui tu es + Code session + Durée validité",
            "Ticket: Qui tu es + Quel service + Code + Durée",
            "",
            "❓ Q3: Contre le rejeu? (1.5pts)",
            "Horloge • Expiration • Nonces • Usage unique • Mémoire",
            "",
            "❓ Q4: Pourquoi TGS? (1pt)",
            "• AS vérifie 1 fois, TGS donne tickets",
            "• Moins de charge",
            "• Pas besoin se reconnecter",
            "",
            "❓ Q5: Améliorer? (1pt)",
            "• Chiffrement fort (AES)",
            "• Certificats (PKINIT)",
            "• Double auth (MFA)",
            "• Annuler tickets"
          ],
          formula: "AS donne TGT → TGS donne Ticket → Accès Serveur"
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