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
          content: "Ensemble qui gère et échange l'information (ordinateurs, logiciels, BD, users)",
          examples: ["Serveurs", "Applications", "Bases de données", "Utilisateurs"]
        },
        {
          id: "ssi",
          title: "🛡️ SSI - Sécurité des SI",
          content: "Protection du SI : empêcher attaques, garder données confidentielles, intègres et disponibles",
          examples: ["Pare-feu", "Cryptage", "Antivirus", "Contrôle d'accès"]
        },
        {
          id: "classification",
          title: "📋 Classification Sécurité",
          content: "4 types de protection",
          examples: [
            "🏢 Physique: caméras, badges",
            "💻 Informatique: antivirus, mots de passe",
            "📡 Communications: VPN, HTTPS",
            "⚙️ Opérationnelle: contrôles, sauvegardes"
          ]
        },
        {
          id: "cyberattaques",
          title: "⚠️ Cyberattaques Courantes",
          content: "Attaques pour voler, détruire ou modifier des données",
          examples: [
            "🎣 Phishing: email falsifié",
            "🔐 Ransomware: blocage + rançon",
            "👤 Usurpation d'identité"
          ]
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
          content: "Faiblesse exploitable dans le système",
          examples: ["Mot de passe faible", "Logiciel non à jour", "Absence de contrôle", "Erreur humaine"],
          formula: "Une faille que l'attaquant peut exploiter"
        },
        {
          id: "menace",
          title: "👹 Menace = Exploitation",
          content: "Acteur qui profite de la porte ouverte",
          examples: ["Pirate informatique", "Virus", "Coupure de courant", "Employé malveillant"],
          formula: "Celui qui entre par la porte"
        },
        {
          id: "risque",
          title: "💥 Risque = Conséquence",
          content: "Probabilité qu'une menace exploite une vulnérabilité",
          examples: ["Vol de données", "Arrêt de service", "Perte financière"],
          formula: "R = Menace × Vulnérabilité / Contre-mesure"
        },
        {
          id: "matrice",
          title: "📊 Matrice des Risques 5×5",
          content: "Classification par Impact × Fréquence",
          examples: [
            "🟢 Faible: Impact faible + rare",
            "🟡 Moyen: Impact moyen",
            "🔴 Critique: Impact fort + fréquent"
          ]
        },
        {
          id: "types-attaques",
          title: "🎯 4 Types d'Attaques",
          content: "Selon l'objectif de l'attaque",
          examples: [
            "🚫 Interruption: rendre indisponible (DoS/DDoS)",
            "👂 Interception: espionner (MITM)",
            "🎭 Fabrication: fausses infos (Phishing)",
            "✏️ Modification: altérer données (XSS, SQLi)"
          ]
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
          content: "Objectifs de sécurité essentiels",
          examples: [
            "🔒 Confidentialité: accès autorisé uniquement",
            "✅ Authentification: prouver l'identité",
            "📝 Non-répudiation: pas de déni d'action",
            "⚡ Disponibilité: service accessible",
            "🔐 Intégrité: données non modifiées"
          ]
        },
        {
          id: "attaques-types",
          title: "🔍 Typologie des Attaques",
          content: "Classées selon leur origine et mode",
          examples: [
            "👨‍💼 Internes: employé malveillant",
            "🌐 Externes: depuis Internet (DoS, DHCP Spoofing)",
            "👁️ Passives: observation (Sniffing)",
            "⚔️ Actives: modification (SQLi, XSS)"
          ]
        },
        {
          id: "attaques-candi",
          title: "🎯 Attaques par Fonction",
          content: "Ciblant chaque pilier CANDI",
          examples: [
            "C: Sniffing, Phishing, Scan ports",
            "A: Brute force, Usurpation IP/ARP",
            "N: DHCP Starvation/Spoofing",
            "D: DoS/DDoS, Smurf, SYN Flood",
            "I: SQL Injection, XSS, Buffer Overflow"
          ]
        },
        {
          id: "protections",
          title: "🛡️ Moyens de Protection",
          content: "Contre-mesures pour chaque pilier",
          examples: [
            "C → SSL/TLS, VPN",
            "A → MFA, mots de passe forts",
            "N → Signature numérique, logs",
            "D → Pare-feu, anti-DDoS, backups",
            "I → Hash, validation entrées, updates"
          ]
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
          content: "1 seule clé pour chiffrer et déchiffrer",
          examples: ["AES, DES", "✅ Rapide", "❌ Partage de clé difficile"],
          formula: "Alice & Bob partagent la même clé secrète"
        },
        {
          id: "asym",
          title: "🔐 Chiffrement Asymétrique",
          content: "2 clés: publique (chiffrer) + privée (déchiffrer)",
          examples: ["RSA, ECC", "✅ Pas d'échange de clé", "❌ Plus lent", "⚠️ Vulnérable MITM"],
          formula: "Bob a clé publique + privée. Alice chiffre avec publique de Bob"
        },
        {
          id: "hash",
          title: "# Hachage",
          content: "Empreinte unique de longueur fixe",
          examples: ["SHA-256, MD5", "Unidirectionnel", "Vérifie l'intégrité"],
          formula: "h(message) = hash fixe. Si message change, hash change"
        },
        {
          id: "signature",
          title: "✍️ Signature Numérique",
          content: "Prouve identité + intégrité",
          examples: [
            "Chiffrement: clé privée → signature",
            "Vérification: clé publique → validation"
          ],
          formula: "Authentification + Non-répudiation"
        },
        {
          id: "pki",
          title: "🏢 PKI & CA",
          content: "Infrastructure de gestion des certificats",
          examples: [
            "CA: délivre certificats",
            "RA: vérifie identités",
            "CRL: liste révocations",
            "Repository: base certificats"
          ],
          formula: "Système de confiance pour clés publiques"
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
          title: "📋 EBIOS - Méthodologie",
          content: "Analyse et gestion des risques SI",
          examples: [
            "1. Analyser contexte",
            "2. Événements redoutés",
            "3. Scénarios menaces",
            "4. Évaluer risques",
            "5. Traiter risques"
          ]
        },
        {
          id: "iso27001",
          title: "🏆 ISO 27001 - SMSI",
          content: "Système de Management de la Sécurité",
          examples: [
            "Cycle PDCA (Plan-Do-Check-Act)",
            "Protège Confidentialité",
            "Garantit Intégrité",
            "Assure Disponibilité"
          ]
        },
        {
          id: "iso27005",
          title: "📊 ISO 27005 - Risques",
          content: "Gestion structurée des risques",
          examples: [
            "Identifier risques",
            "Analyser",
            "Évaluer",
            "Traiter (réduction, acceptation, transfert)"
          ]
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
          title: "🎯 C'est Quoi ?",
          content: "Simuler attaques pour trouver vulnérabilités avant les hackers",
          examples: ["Test interne", "Test externe", "Test web", "Ingénierie sociale"],
          formula: "Comme essayer d'ouvrir la porte de ta maison pour voir si c'est facile"
        },
        {
          id: "phases",
          title: "🔄 Les 6 Phases",
          content: "Processus complet du pentesting",
          examples: [
            "1. Planification: objectifs",
            "2. Reconnaissance: info sur cible",
            "3. Scan: chercher vulnérabilités",
            "4. Exploitation: exploiter failles",
            "5. Maintien: rester caché",
            "6. Rapport: solutions"
          ]
        },
        {
          id: "outils",
          title: "🛠️ Outils Essentiels",
          content: "Arsenal du pentester",
          examples: [
            "Kali Linux: OS spécialisé",
            "Nmap: scanner réseau",
            "Metasploit: exploitation",
            "Burp Suite: sécurité web",
            "Wireshark: analyse trafic"
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
              CYBERSECURITY PRO
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
                      <div className="bg-gray-900/80 border border-gray-700 rounded-lg p-4">
                        <div className="text-sm font-mono text-cyan-400 mb-2">&gt; DESCRIPTION:</div>
                        <p className="text-gray-300 leading-relaxed">
                          {section.content}
                        </p>
                      </div>
                      
                      {section.formula && (
                        <div className="bg-gradient-to-r from-cyan-500/10 to-green-500/10 border border-cyan-500/30 rounded-lg p-4">
                          <div className="flex items-center gap-2 mb-2">
                            <Cpu className="w-4 h-4 text-cyan-400" />
                            <div className="text-xs font-mono text-cyan-400">&gt; FORMULE_CLÉ:</div>
                          </div>
                          <div className="text-cyan-300 font-mono text-sm bg-black/30 p-3 rounded border border-cyan-500/20">
                            {section.formula}
                          </div>
                        </div>
                      )}
                      
                      <div className="space-y-2">
                        <div className="text-xs font-mono text-gray-500 mb-3">&gt; EXEMPLES_PRATIQUES:</div>
                        {section.examples.map((example, idx) => (
                          <div
                            key={idx}
                            className="group/item bg-gray-900/50 border border-gray-700 hover:border-cyan-500/50 rounded-lg p-4 transition-all hover:bg-gray-800/50"
                          >
                            <div className="flex items-start gap-3">
                              <div className="text-cyan-400 font-mono text-xs mt-1">▹</div>
                              <div className="text-gray-300 text-sm flex-1">{example}</div>
                            </div>
                          </div>
                        ))}
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
            [SYSTÈME_ACTIVÉ] • VERSION_2024 • SÉCURITÉ_MAXIMALE
          </p>
        </div>

        <div className="mt-12 pt-8 border-t border-gray-800/10">
          <div className="flex items-center justify-center gap-2 text-gray-600">
            <Shield className="w-4 h-4 text-blue-600" />
            <p className="text-sm">
              Développé avec expertise par{' '}
              <span className="font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                Mohamed AZZAM
              </span>
            </p>
            <Shield className="w-4 h-4 text-purple-600" />
          </div>
          <p className="text-xs text-gray-400 mt-2">© 2024 - Guide d'étude en Sécurité Informatique</p>
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