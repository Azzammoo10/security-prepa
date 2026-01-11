import React, { useState } from 'react';
import { Book, Shield, Lock, AlertTriangle, Network, Bug, Eye, Server, Users, CheckCircle, Terminal, Cpu, Fingerprint } from 'lucide-react';
import RiskMatrix from './RiskMatrix';

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
          title: "🖥️ SI - Système d'Information ❌ Non Inclus",
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
          title: "📋 Classification Sécurité ❌ Non Inclus",
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
          title: "⚠️ Cyberattaques Courantes ❌ Non Inclus",
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
          title: "👹 Menace  = Exploitation de la Vulnerabilite",
          content: "C’est l’exploitation d’une vulnérabilité par un acteur malveillant.• Elle peut être intentionnelle (attaque,piratage) ou non intentionnelle (erreur humaine)",
          examples: [
            "👨‍💻 Pirate informatique (Hacker): black hat, script kiddie",
            "🦠 Virus/Malware: programme malveillant automatisé",
            "⚡ Coupure de courant: menace environnementale",
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
          formula: "Risque = (Menace × Vulnérabilité ) / Contre-mesure | R = P × I (Probabilité × Impact)"
        },
        {
          id: "matrice",
          title: "📊 Matrice des Risques 5×5 Interactive",
          isInteractive: true,
          component: RiskMatrix
        },
        {
          id: "types-attaques",
          title: "🎯 4 Types d'Attaques ❌ Non Inclus",
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
          title: "🎯 CANDI - Les 5 Piliers de la Sécurité",
          content: "Les 5 objectifs fondamentaux de la SSI. Chaque pilier a ses attaques typiques et contre-mesures adaptées.",
          examples: [
            "C - CONFIDENTIALITÉ (Secrète):",
            "  Définition: Seules les personnes autorisées peuvent lire les données",
            "  Exemple: Dossier médical lisible uniquement par le médecin",
            "",
            "  Attaques typiques:",
            "    • Sniffing (Wireshark) - Écoute du trafic réseau",
            "    • Phishing - Faux emails bancaires pour voler identifiants",
            "",
            "  Protections:",
            "    • HTTPS/SSL/TLS - Chiffrement des communications",
            "    • VPN - Tunnel chiffré pour naviguer en sécurité",
            "",
            "",
            "A - AUTHENTIFICATION (Qui es-tu?):",
            "  Définition: Prouver son identité de manière certaine",
            "  Exemple: Déverrouiller son téléphone avec empreinte + code PIN",
            "",
            "  Attaques typiques:",
            "    • Brute Force - Tester tous les mots de passe possibles",
            "    • Credential Stuffing - Réutiliser des mots de passe volés ailleurs",
            "",
            "  Protections:",
            "    • MFA/2FA - Double vérification (SMS, app Authenticator, biométrie)",
            "    • Politique forte - Minimum 12 caractères, complexité, changement régulier",
            "",
            "",
            "N - NON-RÉPUDIATION (Preuve):",
            "  Définition: Impossible de nier avoir fait une action",
            "  Exemple: Signature électronique sur un contrat = preuve juridique",
            "",
            "  Attaques typiques:",
            "    • DHCP Spoofing - Faux serveur pour usurper identité réseau",
            "    • Log Tampering - Effacer ses traces dans les journaux",
            "",
            "  Protections:",
            "    • Signature numérique RSA/ECDSA - Preuve de l'auteur",
            "    • Logs SIEM horodatés - Journaux infalsifiables et centralisés",
            "",
            "",
            "D - DISPONIBILITÉ (Toujours accessible):",
            "  Définition: Le service doit fonctionner 24/7 sans interruption",
            "  Exemple: Site Amazon accessible même pendant le Black Friday",
            "",
            "  Attaques typiques:",
            "    • DDoS - Saturation du site (ex: Mirai botnet attaque Dyn 2016)",
            "    • Ransomware - Chiffre les fichiers (ex: WannaCry 2017 paralysant NHS)",
            "",
            "  Protections:",
            "    • Anti-DDoS Cloudflare - Absorbe le trafic malveillant",
            "    • Backups 3-2-1 - 3 copies, 2 supports, 1 hors site",
            "",
            "",
            "",
            "I - INTÉGRITÉ (Non modifié):",
            "  Définition: Les données n'ont pas été altérées",
            "  Exemple: Fichier téléchargé vérifié par hash SHA-256",
            "",
            "  Attaques typiques:",
            "    • SQL Injection - ' OR '1'='1 pour contourner authentification",
            "    • Man-in-the-Middle - Modifier les données en transit",
            "",
            "  Protections:",
            "    • Hash SHA-256 - Empreinte unique pour détecter modification",
            "    • WAF - Firewall applicatif bloquant les injections"
          ],
          formula: "CANDI = C(onfidentialité) + A(uthentification) + N(on-répudiation) + D(isponibilité) + I(ntégrité)"
        },
        {
          id: "attaques-types",
          title: "🔍 Typologie des Attaques",
          content: "Classification selon 2 axes: ORIGINE (qui attaque?) et MODE (comment?). 4 combinaisons possibles.",
          examples: [
            "AXE 1: ORIGINE DE L'ATTAQUE",
            "",
            "INTERNE (Insider Threat):",
            "  • Qui? Employé mécontent, stagiaire négligent, prestataire",
            "  • Danger: Accès légitime + connaissance du SI",
            "  • Stats: 34% des incidents de sécurité en 2024",
            "  • Exemples:",
            "    - Vol de données clients avant démission",
            "    - Installation d'une backdoor pour accès futur",
            "    - Sabotage de serveurs par vengeance",
            "",
            "EXTERNE:",
            "  • Qui? Hackers, groupes cybercriminels, États-nations",
            "  • Origine: Internet, Wi-Fi public, réseau non sécurisé",
            "  • Exemples:",
            "    - Attaque DDoS depuis botnet",
            "    - Exploitation de vulnérabilité 0-day",
            "    - Campagne phishing massive",
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            "AXE 2: MODE OPÉRATOIRE",
            "",
            "PASSIVE (Écoute silencieuse):",
            "  • Objectif: Observer sans se faire détecter",
            "  • Caractéristique: Aucune modification du système",
            "  • Détection: Très difficile (furtif)",
            "  • Impact: Compromission de la CONFIDENTIALITÉ",
            "  • Exemples:",
            "    - Sniffing Wireshark sur Wi-Fi public",
            "    - Analyse de trafic pour cartographier réseau",
            "    - Écoute de communications non chiffrées",
            "",
            "ACTIVE (Modification/Perturbation):",
            "  • Objectif: Modifier, détruire ou perturber",
            "  • Caractéristique: Laisse des traces dans les logs",
            "  • Détection: Plus facile (IDS, anomalies)",
            "  • Impact: Compromission INTÉGRITÉ + DISPONIBILITÉ",
            "  • Exemples:",
            "    - SQL Injection pour modifier base de données",
            "    - DDoS pour rendre service indisponible",
            "    - Modification de fichiers système",
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            "LES 4 COMBINAISONS:",
            "  1. Interne + Passive = Employé qui espionne discrètement",
            "  2. Interne + Active = Sabotage par employé mécontent",
            "  3. Externe + Passive = Hacker qui fait du reconnaissance",
            "  4. Externe + Active = DDoS, Ransomware, Defacement"
          ],
          formula: "Attaque = [Interne ∪ Externe] × [Passive ∪ Active] = 4 scénarios"
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
          id: "intro-crypto",
          title: "🔐 1. Cryptographie ❌ Non Inclus",
          content: "La cryptographie permet de protéger les données en les rendant illisibles pour les personnes non autorisées",
          examples: [
            "📊 Deux grands types de chiffrement:",
            "  • Chiffrement symétrique (1 clé partagée)",
            "  • Chiffrement asymétrique (2 clés différentes)"
          ],
          formula: "Cryptographie = Protection des données par chiffrement"
        },
        {
          id: "sym",
          title: "🔑 A. Chiffrement Symétrique",
          content: "Une seule clé utilisée pour chiffrer et déchiffrer. Les deux personnes doivent partager la même clé secrète",
          examples: [
            "🔐 Principe:",
            "  • Une seule clé partagée entre Alice et Bob",
            "  • Même clé pour chiffrer ET déchiffrer",
            "",
            "📝 Exemples d'algorithmes:",
            "  • AES (Advanced Encryption Standard)",
            "  • DES (Data Encryption Standard)",
            "",
            "✅ Avantages:",
            "  • (++) Rapide",
            "",
            "❌ Inconvénients:",
            "  • (--) La clé doit être transmise de manière sûre"
          ],
          formula: "1 clé secrète partagée = Chiffrement + Déchiffrement"
        },
        {
          id: "asym",
          title: "🔐 B. Chiffrement Asymétrique",
          content: "Utilise deux clés différentes : Clé publique pour chiffrer, Clé privée pour déchiffrer",
          examples: [
            "🔑 Principe:",
            "  1. Bob kaydir clé publique + clé privée",
            "  2. Alice katsift msg mchifré b clé publique dyal Bob",
            "  3. Bob kay7el msg b clé privée dyalou",
            "",
            "📝 Exemples d'algorithmes:",
            "  • RSA (Rivest-Shamir-Adleman)",
            "  • ECC (Elliptic Curve Cryptography)",
            "",
            "✅ Avantages:",
            "  • (++) Pas besoin d'échanger la clé secrète",
            "",
            "❌ Inconvénients:",
            "  • (--) Plus lent",
            "",
            "⚠️ Vulnérabilité:",
            "  • Vulnérable à l'attaque MITM (Man-in-the-Middle)",
            "  • Interception de clé publique possible"
          ],
          formula: "Clé publique (chiffrer) + Clé privée (déchiffrer) = Asymétrique"
        },
        {
          id: "hash",
          title: "# 2. Hachage (Hashing) ❌ Non Inclus",
          content: "Le hachage transforme un message en une empreinte unique (hash) de longueur fixe",
          examples: [
            "🔢 Fonctions de hachage:",
            "  • Unidirectionnel (impossible de retrouver le message)",
            "  • Même entrée = même hash",
            "  • Deux messages différents → jamais nafs hash",
            "",
            "📝 Exemples:",
            "  • SHA-256 (Secure Hash Algorithm)",
            "  • MD5 (Message Digest)",
            "",
            "✅ Utilité:",
            "  • Vérifie l'intégrité du message",
            "  • Wach le message tbdel wla la",
            "",
            "💡 Exemple:",
            "  • Katdir fonction hachage: h(message) = hash",
            "  • Ila tbdel chi 7aja f message → hash kaytbdel aussi"
          ],
          formula: "h(message) = hash fixe | Message change → Hash change"
        },
        {
          id: "signature",
          title: "✍️ 3. Signature Numérique (ou électronique ou digitale) ❌ Non Inclus",
          content: "La signature numérique prouve l'identité de l'expéditeur et l'intégrité du message",
          examples: [
            "🔐 Principe:",
            "  • L'expéditeur chiffre l'empreinte (hash) du message avec sa clé privée",
            "  • Ce hash chiffré = signature",
            "  • Le destinataire vérifie avec la clé publique de l'expéditeur",
            "",
            "✅ Ce que prouve la signature:",
            "  • Qui a envoyé le message (identité)",
            "  • Que le contenu n'a pas changé (intégrité)"
          ],
          formula: "Signature = Chiffrer(Hash(message), Clé_privée) | Vérifier avec Clé_publique"
        },
        {
          id: "ca",
          title: "🏛️ 4. Autorité de Certification (CA) ❌ Non Inclus",
          content: "Une CA (Certification Authority) est un organisme de confiance qui certifie les clés publiques des utilisateurs",
          examples: [
            "🔑 Rôle de la CA:",
            "  • Vérifie l'identité des utilisateurs",
            "  • Délivre un certificat numérique (carte d'identité électronique)",
            "  • Gère la liste des certificats révoqués (CRL)",
            "",
            "🎯 Objectif:",
            "  • Assurer CANDI:",
            "    - Confidentialité",
            "    - Authenticité",
            "    - Non-répudiation",
            "    - Disponibilité",
            "    - Intégrité",
            "",
            "✅ Garantie:",
            "  • La CA confirme que la clé publique appartient bien à la bonne personne"
          ],
          formula: "CA = Organisme de confiance qui certifie les clés publiques"
        },
        {
          id: "pki",
          title: "🏢 5. PKI (Public Key Infrastructure) ❌ Non Inclus",
          content: "C'est le système qui gère les certificats et les clés publiques dans une organisation",
          examples: [
            "🏗️ Composants principaux:",
            "  • CA (Certification Authority) → délivre les certificats",
            "  • RA (Registration Authority) → vérifie les identités",
            "  • CRL Issuer → publie les certificats révoqués",
            "  • Repository → base de données contenant les certificats",
            "",
            "✅ Utilité:",
            "  • Gérer les certificats (création, renouvellement, révocation)",
            "  • Maintenir la confiance dans les échanges numériques",
            "  • Éviter l'usurpation d'identité et l'attaque MITM",
            "",
            "💡 En résumé:",
            "  • PKI = système li kaygér les clés, certificats, w nass li 3andhom confiance"
          ],
          formula: "PKI = CA + RA + CRL + Repository"
        },
        {
          id: "kerberos",
          title: "🎫 Kerberos - Authentification ❌ Non Inclus",
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
          title: "🎯 Démarche de Gestion des Risques ❌ Non Inclus",
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
          title: "📋 EBIOS - Méthodologie ❌ Non Inclus",
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
            "  • Kartl3b dawr dyal hacker (éthique) f système bash tchouf lmochkil 9bel ma ykoun chi hacker 7a9i9i",
            "  • Une fois nl9aw probleme kandiro rapport o n9tr7o solutions, bax teams responsables y9dro y7mio system dyalhom",
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
          title: "📊 Types de Pentesting ❌ Non Inclus",
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
          title: "🔄 Les 6 Phases du Pentest ❌ Non Inclus",
          content: "Méthodologie structurée pour mener un test d'intrusion efficace",
          examples: [
            "1️⃣ PLANIFICATION:",
            "  • Définir les objectifs du test",
            "  • Établir le périmètre (quoi tester?)",
            "  • Exemple: Tester uniquement le site web, pas le réseau interne",
            "",
            "2️⃣ RECONNAISSANCE:",
            "  • Collecter des informations sur la cible",
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
          title: "🛠️ Outils du Pentester ❌ Non Inclus",
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
          title: "💡 Exemples Pratiques ❌ Non Inclus",
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
      title: "📝 TD & Correction",
      icon: CheckCircle,
      color: "from-green-500 to-emerald-600",
      sections: [
        {
          id: "ex1",
          title: "Exercice 1 - QCM Sécurité des SI",
          content: "Questions à choix multiples sur les fonctions de sécurité et mécanismes d'authentification",
          examples: [
            "1. Quelle est la fonction de sécurité qui garantit qu'un actif est accessible uniquement aux entités autorisées?",
            "   ✅ La confidentialité",
            "   ❌ L'intégrité",
            "   ❌ La disponibilité",
            "",
            "2. Quelle est la fonction de sécurité qui assure qu'un actif devra répondre aux demandes des entités autorisées?",
            "   ❌ L'intégrité",
            "   ✅ La disponibilité",
            "   ❌ L'authentification",
            "",
            "3. Quels sont les services offerts par le contrôle d'accès?",
            "   ✅ L'authentification",
            "   ❌ L'intégrité",
            "   ❌ La non-répudiation",
            "",
            "4. Le contrôle d'accès:",
            "   ✅ Similaire au modèle AAA (Authentication, Authorization, Accounting)",
            "   ❌ Vérifie l'intégrité des informations échangées",
            "   ✅ Dicte qui est autorisé à utiliser les ressources",
            "",
            "5. Un actif est:",
            "   ❌ Une ressource utilisée par tout le monde",
            "   ✅ Une ressource dont l'accès est contrôlé",
            "   ❌ Une ressource dont l'accès n'est autorisé à personne",
            "",
            "6. L'authentification par carte à puce est une méthode d'authentification basée sur:",
            "   ❌ Ce que l'utilisateur connaît",
            "   ✅ Ce que l'utilisateur possède",
            "   ❌ Les facteurs biométriques d'un utilisateur",
            "",
            "7. Quels sont les propositions qui peuvent être des facteurs biométriques permettant l'authentification?",
            "   ✅ Empreinte",
            "   ❌ Jeton",
            "   ✅ Voix",
            "   ❌ Code PIN"
          ],
          formula: "AAA = Authentication + Authorization + Accounting"
        },
        {
          id: "ex2",
          title: "Exercice 2 - Tableau Mécanismes de Sécurité",
          content: "Remplir le tableau en indiquant la fonction assurée par chaque mécanisme",
          examples: [
            "Mécanisme | Contrôle d'accès | Cryptage | SIEM | Signature numérique | Authentification MFA",
            "",
            "CONFIDENTIALITÉ:",
            "  • Contrôle d'accès: ✅",
            "  • Cryptage: ✅",
            "  • SIEM: -",
            "  • Signature numérique: -",
            "  • MFA: -",
            "",
            "AUTHENTIFICATION:",
            "  • Contrôle d'accès: ✅",
            "  • Cryptage: -",
            "  • SIEM: -",
            "  • Signature numérique: ✅",
            "  • MFA: ✅",
            "",
            "NON-RÉPUDIATION:",
            "  • Contrôle d'accès: -",
            "  • Cryptage: -",
            "  • SIEM: ✅",
            "  • Signature numérique: ✅",
            "  • MFA: -",
            "",
            "DISPONIBILITÉ:",
            "  • Contrôle d'accès: -",
            "  • Cryptage: -",
            "  • SIEM: ✅",
            "  • Signature numérique: -",
            "  • MFA: -",
            "",
            "INTÉGRITÉ:",
            "  • Contrôle d'accès: -",
            "  • Cryptage: ✅",
            "  • SIEM: -",
            "  • Signature numérique: ✅",
            "  • MFA: -"
          ],
          formula: "Mécanismes complémentaires pour assurer CANDI"
        },
        {
          id: "ex3",
          title: "Exercice 3 - Questions Techniques",
          content: "Questions sur l'authentification, attaques DoS, IDS/IPS et malwares",
          examples: [
            "1. Comment un utilisateur peut-il effectuer l'authentification?",
            "   • Ce qu'il connaît (mot de passe ou code PIN)",
            "   • Ce qu'il possède (clé USB, puce, jetons)",
            "   • Ce qu'il est (biométrie)",
            "   • Ce qu'il avait (autorisation, privilège)",
            "",
            "2. Pour réaliser une attaque DoS, on peut:",
            "   ✅ Inonder un réseau avec des trames",
            "   ❌ Scanner et capturer le trafic",
            "   ✅ Empêcher l'accès à un service",
            "   ❌ Chiffrer les échanges",
            "",
            "3. Quelle notion représente un IDS et laquelle représente un IPS?",
            "   IDS: Détecte et surveille mais il n'agit pas seul",
            "   IPS: Accepte ou rejette des paquets en fonction d'un ensemble de règles",
            "   Les deux: Analyser le trafic et le comparer aux menaces connues",
            "",
            "4. Quelle notion représente un virus et laquelle représente un ver?",
            "   Virus: Déclenché par une interaction avec un fichier infecté",
            "   Ver: Programme autonome qui se reproduit indépendamment"
          ],
          formula: "IDS = Détection | IPS = Prévention + Détection"
        },
        {
          id: "ex4",
          title: "Exercice 4 - Backdoor & Cheval de Troie",
          content: "Analyse des portes dérobées et chevaux de Troie",
          examples: [
            "1. Qu'est-ce qu'une porte dérobée (backdoor)?",
            "   Une porte dérobée est une méthode clandestine permettant de contourner",
            "   les procédures d'authentification normales pour obtenir un accès non",
            "   autorisé à un système. Les développeurs de logiciels et de matériel",
            "   installent parfois des portes dérobées dans leurs propres produits pour",
            "   conserver l'accès à des fins de dépannage.",
            "",
            "2. Comment un attaquant peut-il procéder pour en installer une?",
            "   L'activation d'une porte dérobée peut se faire au moyen d'un logiciel",
            "   malveillant de type vers, qui va exploiter une faille de sécurité dans le",
            "   produit et se propager automatiquement à tous les ordinateurs d'un réseau.",
            "   Plus simplement, le mot de passe par défaut d'un produit peut faire office",
            "   de backdoor si l'utilisateur ne prend pas la peine de le changer.",
            "",
            "3. Qu'est-ce qu'un cheval de Troie?",
            "   Le cheval de Troie prend l'apparence d'un logiciel existant, légitime et",
            "   parfois même réputé, mais qui aura été modifié pour cacher un parasite.",
            "",
            "4. Comment un attaquant peut-il procéder pour en installer un?",
            "   L'activation d'un cheval de Troie peut s'exécuter en téléchargeant des",
            "   programmes et exécutables - Exploitation de failles - Ingénierie sociale -",
            "   Pièces jointes et fichiers envoyés - Connexion à un périphérique externe",
            "   infecté - Absence de logiciel de protection."
          ],
          formula: "Backdoor = Accès caché | Trojan = Programme déguisé"
        },
        {
          id: "ex5",
          title: "Exercice 5 - Codes Malveillants & Antivirus",
          content: "Comment les malwares évitent la détection et techniques de détection antivirus",
          examples: [
            "1. Comment un code malveillant empêche le logiciel antivirus de le détecter?",
            "",
            "   Les codes malveillants peuvent empêcher les antivirus de fonctionner",
            "   correctement, en arrêtant ces programmes ou en bloquant les connexions",
            "   vers les sites de mise à jour de l'antivirus.",
            "",
            "   Les codes malveillants plus avancés contiennent un rootkit qui modifie le",
            "   comportement du système d'exploitation afin que celui-ci ne divulgue pas",
            "   la présence du code malveillant. Par exemple, il peut modifier les appels",
            "   système utilisés pour lister le contenu d'un répertoire ou les processus",
            "   actifs. Cela cause l'échec de signalisation de la présence du code malveillant.",
            "",
            "2. Quelle technique utilise un antivirus pour détecter les programmes malveillants?",
            "",
            "   Recherche de signatures: consiste à établir la liste de tous les codes",
            "   malveillants connus et à rechercher leur signature, c'est-à-dire une suite",
            "   de bits caractéristique, dans des fichiers ou du trafic reçu.",
            "",
            "   Analyse du comportement: consiste à étudier le comportement d'un logiciel",
            "   pour découvrir d'éventuelles actions malveillantes."
          ],
          formula: "Détection = Signatures + Comportement"
        },
        {
          id: "ex6",
          title: "Exercice 6 - Décomposition du Risque Wi-Fi",
          content: "Analyser les risques liés à l'utilisation du Wi-Fi dans une organisation",
          examples: [
            "Ressource: Réseau WiFi",
            "",
            "Vulnérabilité potentielle: Administration à distance",
            "",
            "Agent de menace possible: Un pirate",
            "",
            "Méthode d'attaque probable: Intrusion",
            "",
            "Fonctions de sécurité endommagées: Confidentialité",
            "",
            "Impact potentiel sur l'organisme: Perte d'information",
            "",
            "Type d'attaque:",
            "  • Attaque passive: Espionnage",
            "  • Attaque active: Usurpation d'identité, modification des informations"
          ],
          formula: "Risque WiFi = Vulnérabilité × Menace × Impact"
        },
        {
          id: "ex7",
          title: "Exercice 7 - Matrice de Risque",
          content: "Remplir la matrice de risque pour différents scénarios",
          examples: [
            "Scénarios à évaluer (Impact × Probabilité):",
            "",
            "1. Authentification d'un employé à distance sans mesure de sécurité",
            "   → RISQUE ÉLEVÉ",
            "",
            "2. Authentification d'un employé à distance avec des mesures de sécurité",
            "   → RISQUE FAIBLE",
            "",
            "3. Paiement en ligne avec des mesures de sécurité",
            "   → RISQUE MODÉRÉ",
            "",
            "4. Paiement en ligne sans mesures de sécurité",
            "   → RISQUE CRITIQUE",
            "",
            "5. Base de données de l'entreprise dans une DMZ",
            "   → RISQUE MODÉRÉ",
            "",
            "6. Paiement avec carte bancaire sans contact",
            "   → RISQUE FAIBLE",
            "",
            "7. Transactions bancaires sur un smartphone",
            "   → RISQUE MODÉRÉ",
            "",
            "8. Utilisateur sur les réseaux sociaux",
            "   → RISQUE FAIBLE",
            "",
            "9. Transactions avec smart Watch",
            "   → RISQUE MODÉRÉ",
            "",
            "10. Base de données avec des mesures de sécurité",
            "    → RISQUE ACCEPTABLE"
          ],
          formula: "Niveau de risque = Impact × Probabilité"
        },
        {
          id: "ex8",
          title: "Exercice 8 - Relations entre Notions",
          content: "Quelle est la relation entre les notions suivantes",
          examples: [
            "Relations entre:",
            "",
            "CIBLE:",
            "  • Est visée par une menace",
            "  • Contient des vulnérabilités",
            "  • Nécessite des contrôles",
            "",
            "CONTRÔLE:",
            "  • Protège la cible",
            "  • Mitige le risque",
            "  • Préserve les actifs",
            "",
            "GARANTIT:",
            "  • Le contrôle garantit la sécurité",
            "  • La mesure garantit la protection",
            "",
            "PRÉSERVE:",
            "  • Le contrôle préserve l'intégrité",
            "  • La sécurité préserve la confidentialité",
            "",
            "PROTÈGE:",
            "  • Le contrôle protège contre les menaces",
            "  • Le chiffrement protège les données",
            "",
            "AFFECTE:",
            "  • La menace affecte la cible",
            "  • Le risque affecte l'organisation",
            "",
            "MITIGE:",
            "  • Le contrôle mitige le risque",
            "  • Les mesures mitigent l'impact"
          ],
          formula: "Menace → Cible ← Contrôle → Mitige → Risque"
        },
        {
          id: "ex9",
          title: "Exercice 9 - Cas Pratique: Café Local",
          content: "Un café local de 10 employés offre le Wi-Fi gratuit et gère ses opérations via cloud",
          examples: [
            "INCIDENT:",
            "  Application de planification bloquée, mot de passe incorrect",
            "  Coordonnées bancaires modifiées chez un fournisseur",
            "  Impossibilité de se connecter à la messagerie professionnelle",
            "",
            "1. Quel est le type de cyberattaque le plus probable?",
            "   Il s'agit d'une attaque de phishing ayant entraîné une usurpation",
            "   d'authentification et une compromission de la messagerie professionnelle.",
            "",
            "2. Quel était le point d'entrée initial probable de l'attaquant?",
            "   Le point d'entrée le plus probable était l'appareil personnel d'un employé",
            "   ou un ordinateur professionnel, via un e-mail ou SMS de phishing (smishing).",
            "",
            "3. Quelles mesures le propriétaire devrait-il prendre immédiatement?",
            "   • Ne pas utiliser l'e-mail, car il est compromis",
            "   • Réinitialiser les mots de passe et en utiliser de nouveaux, forts et uniques",
            "   • Informer tous les employés de l'incident",
            "   • Leur demander de ne cliquer sur aucun lien suspect",
            "   • Demander de réinitialiser leurs mots de passe pour tous les comptes",
            "   • Vérifier les comptes bancaires et relevés financiers",
            "",
            "4. Quels sont les impacts potentiels?",
            "   Court terme:",
            "   • Perte financière due au virement frauduleux",
            "   • Perturbation des opérations et perte de productivité",
            "",
            "   Long terme:",
            "   • Atteinte à la réputation et perte de confiance des clients",
            "   • Amendes réglementaires potentielles (exposition des données clients)",
            "   • Coût de la mise en œuvre de nouvelles mesures de sécurité",
            "",
            "5. Quelles sont les trois mesures de sécurité simples à mettre en œuvre?",
            "   1. Activer l'authentification multifacteur (MFA)",
            "   2. Formation des employés à la sécurité",
            "   3. Utiliser un gestionnaire de mots de passe"
          ],
          formula: "Phishing → Compromission → Usurpation → Impact financier"
        },
        {
          id: "ex10",
          title: "Exercice 10 - Cas Pratique: Boutique en Ligne",
          content: "Petite boutique en ligne vendant des objets artisanaux avec site WordPress",
          examples: [
            "INCIDENT:",
            "  Fenêtre contextuelle 'Vous avez gagné un prix!' sur la section Poterie",
            "  Blocage de l'accès au panneau d'administration",
            "  Page d'accueil dégradée par un message de pirate",
            "",
            "1. Quel type d'attaque pour la fenêtre contextuelle?",
            "   Il s'agit d'une attaque XSS (Cross-Site Scripting). Un attaquant a injecté",
            "   du code malveillant dans le site web. Ce code est stocké sur le serveur et",
            "   chaque fois qu'un visiteur charge la page 'Poterie', son navigateur exécute",
            "   le script malveillant, provoquant l'apparition de la fenêtre contextuelle",
            "   et la redirection.",
            "",
            "2. Quelle attaque a permis d'accéder à la base de données?",
            "   Injection SQL. L'attaquant a probablement trouvé un champ de saisie non",
            "   protégé, comme le formulaire de demande de renseignements sur les produits",
            "   ou le formulaire de connexion. Il aurait saisi un code (' OR '1'='1) au lieu",
            "   d'une question normale, trompant ainsi la base de données et permettant de",
            "   consulter, modifier ou supprimer le contenu de la base de données, y compris",
            "   les identifiants utilisateurs et les données des produits.",
            "",
            "3. Quel était le point le plus vulnérable du site web?",
            "   Le formulaire de demande de renseignements sur les produits personnalisé ou",
            "   tout autre champ de saisie utilisateur mal sécurisé.",
            "",
            "4. Quelles mesures immédiates le propriétaire devrait-il prendre?",
            "   • Mettre le site hors ligne pendant le contact de son hébergeur",
            "   • L'hébergeur peut aider à restaurer le site à partir d'une sauvegarde",
            "   • Restaurer l'intégralité du site web et de la base de données",
            "   • Faire appel à un professionnel de la sécurité pour analyser tous",
            "     les fichiers du site web et la base de données",
            "   • Détecter et supprimer le code malveillant",
            "",
            "5. Quelles pratiques à long terme adopter?",
            "   Validation et nettoyage des entrées:",
            "   • Toutes les entrées utilisateur doivent être traitées comme non fiables",
            "   • Le code du site web doit vérifier et valider les entrées",
            "   • Utiliser des requêtes préparées (Prepared Statements)",
            "   • Encoder les sorties pour éviter XSS",
            "   • Mettre à jour régulièrement WordPress et tous les plugins",
            "   • Installer un WAF (Web Application Firewall)"
          ],
          formula: "XSS + SQL Injection = Compromission totale du site"
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
              {!activeChapterData.isInteractive && (
              <div className="text-right">
                <div className="text-xs font-mono text-gray-500">SECTIONS</div>
                <div className="text-2xl font-bold text-cyan-400">{activeChapterData.sections?.length || 0}</div>
              </div>
              )}
            </div>

            {/* Sections or Interactive Component */}
            {activeChapterData.isInteractive && activeChapterData.component ? (
              <activeChapterData.component />
            ) : (
            <div className="space-y-4">
              {activeChapterData.sections?.map((section, idx) => (
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
                      {section.examples && (
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
                      )}
                      
                      {/* Section interactive pour la matrice */}
                      {section.isInteractive && section.component && (
                        <div className="mt-4">
                          <section.component />
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
            )}
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