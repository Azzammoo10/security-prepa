import React, { useState } from 'react';
import { AlertTriangle, Info } from 'lucide-react';

const RiskMatrix = () => {
  const [selectedCell, setSelectedCell] = useState(null);
  const [hoveredCell, setHoveredCell] = useState(null);

  // Définition de la matrice 5x5
  const probabilityLevels = [
    { id: 5, label: 'Très élevée', value: 5 },
    { id: 4, label: 'Élevée', value: 4 },
    { id: 3, label: 'Moyenne', value: 3 },
    { id: 2, label: 'Faible', value: 2 },
    { id: 1, label: 'Très faible', value: 1 }
  ];

  const impactLevels = [
    { id: 1, label: 'Négligeable', value: 1 },
    { id: 2, label: 'Limité', value: 2 },
    { id: 3, label: 'Important', value: 3 },
    { id: 4, label: 'Critique', value: 4 },
    { id: 5, label: 'Très critique', value: 5 }
  ];

  // Calcul du niveau de risque et couleur
  const getRiskLevel = (probability, impact) => {
    const score = probability * impact;
    
    if (score >= 20) return { level: 'CRITIQUE', color: 'bg-red-600', textColor: 'text-red-600', borderColor: 'border-red-600' };
    if (score >= 15) return { level: 'TRÈS ÉLEVÉ', color: 'bg-red-500', textColor: 'text-red-500', borderColor: 'border-red-500' };
    if (score >= 12) return { level: 'ÉLEVÉ', color: 'bg-orange-500', textColor: 'text-orange-500', borderColor: 'border-orange-500' };
    if (score >= 8) return { level: 'MODÉRÉ', color: 'bg-yellow-500', textColor: 'text-yellow-600', borderColor: 'border-yellow-500' };
    if (score >= 4) return { level: 'FAIBLE', color: 'bg-yellow-400', textColor: 'text-yellow-600', borderColor: 'border-yellow-400' };
    return { level: 'ACCEPTABLE', color: 'bg-green-500', textColor: 'text-green-600', borderColor: 'border-green-500' };
  };

  // Description des niveaux de risque
  const getRiskDescription = (score) => {
    if (score >= 20) return 'Risque inacceptable - Action immédiate requise';
    if (score >= 15) return 'Risque très élevé - Traitement prioritaire';
    if (score >= 12) return 'Risque élevé - Plan d\'action à court terme';
    if (score >= 8) return 'Risque modéré - Surveillance renforcée';
    if (score >= 4) return 'Risque faible - Surveillance normale';
    return 'Risque acceptable - Suivi périodique';
  };

  const handleCellClick = (probability, impact) => {
    const score = probability * impact;
    setSelectedCell({ probability, impact, score });
  };

  return (
    <div className="w-full max-w-7xl mx-auto p-6 bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 rounded-2xl shadow-2xl">
      {/* En-tête */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-8 h-8 text-yellow-400" />
          <h2 className="text-3xl font-bold text-white">Matrice de Priorisation des Risques</h2>
        </div>
        <p className="text-gray-300 text-lg">
          Matrice 5×5 : Plus l'impact et la fréquence sont élevés, plus le risque est critique
        </p>
      </div>

      {/* Légende des couleurs */}
      <div className="mb-6 p-4 bg-white/10 backdrop-blur-sm rounded-lg">
        <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
          <Info className="w-5 h-5" />
          Niveau de Risque
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-green-500 rounded"></div>
            <span className="text-white text-sm">Acceptable (1-3)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-yellow-400 rounded"></div>
            <span className="text-white text-sm">Faible (4-6)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-yellow-500 rounded"></div>
            <span className="text-white text-sm">Modéré (8-10)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-orange-500 rounded"></div>
            <span className="text-white text-sm">Élevé (12-16)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-red-500 rounded"></div>
            <span className="text-white text-sm">Très élevé (15-20)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-red-600 rounded"></div>
            <span className="text-white text-sm">Critique (20-25)</span>
          </div>
        </div>
      </div>

      {/* Matrice */}
      <div className="overflow-x-auto">
        <div className="inline-block min-w-full">
          {/* Label Y (Probabilité/Fréquence) */}
          <div className="flex items-center mb-4">
            <div className="w-40 text-right pr-4">
              <span className="text-white font-bold text-lg rotate-0 inline-block">
                Probabilité / Fréquence →
              </span>
            </div>
          </div>

          <div className="flex">
            {/* Colonne des labels de probabilité */}
            <div className="flex flex-col pr-4">
              {probabilityLevels.map((prob) => (
                <div
                  key={prob.id}
                  className="h-20 flex items-center justify-end mb-1"
                >
                  <span className="text-white font-semibold text-sm whitespace-nowrap">
                    {prob.label}
                  </span>
                </div>
              ))}
            </div>

            {/* Grille de la matrice */}
            <div className="flex-1">
              {/* Cellules de la matrice */}
              {probabilityLevels.map((prob) => (
                <div key={prob.id} className="flex gap-1 mb-1">
                  {impactLevels.map((impact) => {
                    const score = prob.value * impact.value;
                    const risk = getRiskLevel(prob.value, impact.value);
                    const isSelected = selectedCell?.probability === prob.value && selectedCell?.impact === impact.value;
                    const isHovered = hoveredCell?.probability === prob.value && hoveredCell?.impact === impact.value;

                    return (
                      <div
                        key={`${prob.id}-${impact.id}`}
                        onClick={() => handleCellClick(prob.value, impact.value)}
                        onMouseEnter={() => setHoveredCell({ probability: prob.value, impact: impact.value, score })}
                        onMouseLeave={() => setHoveredCell(null)}
                        className={`
                          flex-1 h-20 ${risk.color} rounded-lg cursor-pointer
                          flex items-center justify-center
                          transition-all duration-200
                          ${isSelected ? 'ring-4 ring-white scale-105' : ''}
                          ${isHovered ? 'scale-105 shadow-xl' : 'shadow-md'}
                          hover:shadow-xl
                        `}
                      >
                        <span className="text-white font-bold text-2xl">
                          {score}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ))}

              {/* Labels d'impact (en bas) */}
              <div className="flex mt-2 mb-4">
                {impactLevels.map((impact) => (
                  <div
                    key={impact.id}
                    className="flex-1 text-center"
                  >
                    <span className="text-white font-semibold text-sm">
                      {impact.label}
                    </span>
                  </div>
                ))}
              </div>

              {/* Label X (Impact/Gravité) */}
              <div className="text-center mt-4">
                <span className="text-white font-bold text-lg">
                  ← Impact / Gravité
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Affichage des détails de la cellule sélectionnée */}
      {selectedCell && (
        <div className="mt-8 p-6 bg-white/10 backdrop-blur-sm rounded-lg border-2 border-white/20">
          <h3 className="text-white font-bold text-xl mb-4">Détails du Risque</h3>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-gray-300 mb-2">
                <span className="font-semibold text-white">Score:</span> {selectedCell.score}
              </p>
              <p className="text-gray-300 mb-2">
                <span className="font-semibold text-white">Probabilité:</span> {probabilityLevels.find(p => p.value === selectedCell.probability)?.label}
              </p>
              <p className="text-gray-300 mb-2">
                <span className="font-semibold text-white">Impact:</span> {impactLevels.find(i => i.value === selectedCell.impact)?.label}
              </p>
            </div>
            <div>
              <p className={`font-bold text-lg mb-2 ${getRiskLevel(selectedCell.probability, selectedCell.impact).textColor}`}>
                Niveau: {getRiskLevel(selectedCell.probability, selectedCell.impact).level}
              </p>
              <p className="text-gray-300">
                {getRiskDescription(selectedCell.score)}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Informations supplémentaires */}
      <div className="mt-8 p-4 bg-blue-500/20 backdrop-blur-sm rounded-lg border border-blue-400/30">
        <h3 className="text-white font-semibold mb-3">💡 Comment utiliser cette matrice ?</h3>
        <ul className="text-gray-200 space-y-2 text-sm">
          <li>• <strong>Évaluez la probabilité</strong> qu'un risque se réalise (de très faible à très élevée)</li>
          <li>• <strong>Évaluez l'impact</strong> que ce risque aurait sur l'organisation (de négligeable à très critique)</li>
          <li>• <strong>Le score final</strong> (Probabilité × Impact) détermine la criticité et la priorité de traitement</li>
          <li>• <strong>Cliquez sur une cellule</strong> pour voir les détails et recommandations</li>
        </ul>
      </div>
    </div>
  );
};

export default RiskMatrix;
