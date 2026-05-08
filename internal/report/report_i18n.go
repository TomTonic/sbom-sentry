package report

// translations contains all localized report labels and prose snippets used
// by human-report generation.
//
// Contract for string fields in this struct:
//   - Values are inserted into Markdown output and therefore are plain text
//     or inline Markdown fragments (for example links or inline code spans).
//   - Values are never HTML and must not depend on runtime locale APIs.
//   - Fields ending with "Template" are consumed via fmt.Sprintf and must keep
//     placeholder count/order compatible with their call sites.
//   - Fields ending with "Section", "Label", "Header", "Reason" or "Value"
//     are short UI strings (single-line headings/cell labels).
//   - The noneValue fallback should be a short, language-localized token used
//     when no sample/path value exists.
//
// getTranslations must return a fully populated bundle (no zero-value gaps)
// for every supported language. Unknown language codes intentionally fall back
// to English.
type translations struct {
	title                                  string
	inputSection                           string
	configSection                          string
	rootMetadataSection                    string
	sandboxSection                         string
	extractionSection                      string
	scanSection                            string
	scanSectionLead                        string
	scanTaskEvidenceLabel                  string
	scanNoPackageIDsSection                string
	scanNoPackageIDsLead                   string
	noScanNoPackageIDs                     string
	policySection                          string
	summarySection                         string
	residualRiskSection                    string
	processingIssuesSection                string
	field                                  string
	value                                  string
	source                                 string
	setting                                string
	filename                               string
	filesize                               string
	unitBytes                              string
	skipExtensions                         string
	nameLabel                              string
	manufacturerLabel                      string
	deliveryDateLabel                      string
	policyMode                             string
	interpretMode                          string
	language                               string
	maxDepth                               string
	maxFiles                               string
	maxTotalSize                           string
	maxEntrySize                           string
	maxRatio                               string
	timeout                                string
	progressLevel                          string
	generator                              string
	sandboxName                            string
	sandboxAvail                           string
	unsafeWarning                          string
	unsafeActive                           string
	tableOfContentsSection                 string
	methodOverviewSection                  string
	appendixSection                        string
	componentIndexSection                  string
	componentIndexLead                     string
	noIndexedComponents                    string
	objectID                               string
	packageName                            string
	version                                string
	purl                                   string
	evidencePath                           string
	foundBy                                string
	noEvidenceRecorded                     string
	scanError                              string
	componentsFound                        string
	noComponents                           string
	deliveryPath                           string
	status                                 string
	tool                                   string
	duration                               string
	suppliedBy                             string
	derived                                string
	residualRiskText                       string
	residualRiskProfileLead                string
	residualRiskAbsenceHint                string
	residualRiskPURLCoverage               string
	residualRiskEvidenceCoverage           string
	residualRiskNoComponentTasks           string
	residualRiskFileArtifactCoverage       string
	residualRiskExtensionFilter            string
	residualRiskExtractionGap              string
	residualRiskToolGap                    string
	residualRiskScanGap                    string
	residualRiskMoreDetails                string
	noPolicyDecisions                      string
	noProcessingIssues                     string
	summaryLead                            string
	summaryLeadNoVuln                      string
	vulnEnrichmentNotRequested             string
	vulnEnrichmentStateTemplate            string
	vulnGrypeVersionTemplate               string
	vulnGrypeDBTemplate                    string
	vulnEnrichmentIssuesTemplate           string
	vulnFindingsTemplate                   string
	vulnNoMatchedFindings                  string
	vulnSummaryHeading                     string
	findingVulnMatchesTemplate             string
	findingVulnNoMatches                   string
	findingDeliveryCompositionTemplate     string
	findingExtractionStatusSuccessTemplate string
	findingExtractionStatusFailureTemplate string
	reportHeaderGeneratorVersionTemplate   string
	reportHeaderToolsLabel                 string
	vulnTableName                          string
	vulnTableInstalled                     string
	vulnTableFixedIn                       string
	vulnTableVulnerability                 string
	vulnTableSeverity                      string
	vulnTableEPSS                          string
	vulnTableRisk                          string
	vulnTableKEV                           string
	vulnStatusFoundTemplate                string
	vulnStatusNotAssessableUnavailable     string
	vulnStatusNotAssessableNoID            string
	vulnStatusNone                         string
	vulnDetailSourceTemplate               string
	vulnDetailFixTemplate                  string
	vulnDetailCVSSTemplate                 string
	vulnDetailCVSSNone                     string
	vulnDetailDescriptionTemplate          string
	vulnDetailDescriptionNone              string
	vulnDetailEPSSTemplate                 string
	vulnDetailReferenceTemplate            string
	vulnKEVYes                             string
	vulnKEVNo                              string
	methodLead                             string
	methodBulletTwoPhases                  string
	methodBulletEvidence                   string
	methodBulletDedup                      string
	methodBulletTrust                      string
	methodMoreDetails                      string
	appendixLead                           string
	summaryKeyFindingsSection              string
	summaryAnalysisSection                 string
	summaryVulnSection                     string
	endOfReport                            string
	policyDecisionAt                       string
	linkTwoPhases                          string
	linkScanDetail                         string
	linkFinalSBOMBuild                     string
	linkDeduplication                      string
	linkPackageDetectionReliability        string
	summaryAnalysisProseTemplate           string
	summaryAnalysisMethodRef               string
	findingToolMissingTemplate             string
	findingExtractionGapTemplate           string
	findingScanFailedTemplate              string
	findingPURLCoverageTemplate            string
	findingNoPackageIdentityTemplate       string
	findingNoCriticalLimitations           string
	findingPolicyDecisionsTemplate         string
	findingProcessingIssuesTemplate        string
	processingPipelineLabel                string
	processingExtractionFailedLabel        string
	processingSecurityBlockedLabel         string
	processingToolMissingLabel             string
	processingScanErrorsLabel              string
	processingSourceHeader                 string
	processingLocationHeader               string
	processingClassHeader                  string
	processingStatusHeader                 string
	processingDetectedHeader               string
	processingToolHeader                   string
	processingArchiveTypeHeader            string
	processingArchiveMethodHeader          string
	processingEncryptedHeader              string
	processingPhysicalSizeHeader           string
	processingDetailHeader                 string
	additionalEntriesOmittedTemplate       string
	noneValue                              string
	reasonLabel                            string
	countLabel                             string
	suppressionOperationalFS               string
	suppressionOperationalFSFollowUp       string
	suppressionOperationalLowValue         string
	suppressionOperationalWeakDup          string
	suppressionOperationalPURLDup          string
	suppressionTableDeliveryPath           string
	suppressionTableComponentName          string
	suppressionTableSuppressedBy           string
	extractionSandboxLabel                 string

	componentNormalizationSection  string
	componentNormalizationLead     string
	noSuppressions                 string
	suppressionReasonFSArtifact    string
	suppressionReasonLowValueFile  string
	suppressionReasonWeakDuplicate string
	suppressionReasonPURLDuplicate string
	suppressionReplacedBy          string

	extensionFilterSection              string
	extensionFilterLead                 string
	extensionFilterExtensionsLabel      string
	extensionFilterSkippedLabel         string
	noExtensionFilteredFiles            string
	componentIndexWithPURLSubsection    string
	componentIndexWithoutPURLSubsection string
	occurrencesLabel                    string
	purlsLabel                          string
	componentIDLabel                    string
	suppressedByNoIndexedMatch          string
	suppressedByAmbiguousIndexedMatch   string
	suppressedByReplacementNotIndexed   string
}

// getTranslations returns the translation bundle for the requested language,
// defaulting to English when an unknown code is provided.
func getTranslations(lang string) translations {
	switch lang {
	case "de":
		return translations{
			title:                                  "extract-sbom Prüfbericht",
			inputSection:                           "Eingabedatei",
			configSection:                          "Konfiguration",
			rootMetadataSection:                    "SBOM Stammdaten",
			sandboxSection:                         "Sandbox-Konfiguration",
			extractionSection:                      "Extraktionsprotokoll",
			scanSection:                            "Paketscan-Protokoll",
			policySection:                          "Richtlinienentscheidungen",
			summarySection:                         "Zusammenfassung",
			residualRiskSection:                    "Restrisiko und Einschränkungen",
			processingIssuesSection:                "Verarbeitungsfehler",
			field:                                  "Feld",
			value:                                  "Wert",
			source:                                 "Quelle",
			setting:                                "Einstellung",
			filename:                               "Dateiname",
			filesize:                               "Dateigröße",
			unitBytes:                              "Bytes",
			skipExtensions:                         "skip-extensions",
			nameLabel:                              "Name",
			manufacturerLabel:                      "Hersteller",
			deliveryDateLabel:                      "Lieferdatum",
			policyMode:                             "Richtlinienmodus",
			interpretMode:                          "Interpretationsmodus",
			language:                               "Sprache",
			maxDepth:                               "Maximale Tiefe",
			maxFiles:                               "Maximale Dateien",
			maxTotalSize:                           "Maximale Gesamtgröße",
			maxEntrySize:                           "Maximale Eintragsgröße",
			maxRatio:                               "Maximales Verhältnis",
			timeout:                                "Zeitlimit",
			progressLevel:                          "Fortschritt",
			generator:                              "extract-sbom Build",
			sandboxName:                            "Sandbox",
			sandboxAvail:                           "Verfügbar",
			unsafeWarning:                          "WARNUNG",
			unsafeActive:                           "Unsicherer Modus aktiv — keine Sandbox-Isolation",
			tableOfContentsSection:                 "Inhaltsverzeichnis",
			methodOverviewSection:                  "Verfahren im Kurzüberblick",
			appendixSection:                        "Anhang",
			componentIndexSection:                  "Komponentenindex",
			componentIndexLead:                     "Die Einträge sind nach Paket (Name+Version) gruppiert. Unter jedem Paket werden die konkreten Komponenten-Vorkommen (Objekt-ID = bom-ref im SBOM bzw. artifact.id in Grype) mit ihren Liefer- und Belegpfaden aufgeführt.",
			noIndexedComponents:                    "Keine Komponenten-Vorkommen indexiert.",
			objectID:                               "Objekt-ID",
			packageName:                            "Paket",
			version:                                "Version",
			purl:                                   "PURL",
			evidencePath:                           "Belegpfad",
			foundBy:                                "Erkannt durch",
			noEvidenceRecorded:                     "kein komponentenspezifischer Beleg erfasst",
			scanError:                              "Fehler:",
			componentsFound:                        "Komponenten gefunden",
			noComponents:                           "keine Komponenten gefunden",
			scanSectionLead:                        "Dies ist das Paketscan-Protokoll der untersuchten Inhaltselemente. Die hier aufgeführten Evidenzpfade beziehen sich auf einzelne Inhaltselemente und können mehrere finale Komponenten abdecken. Die maßgebliche komponentenspezifische Evidenz steht im Komponentenindex.",
			scanTaskEvidenceLabel:                  "evidence-path",
			scanNoPackageIDsSection:                "Inhaltselemente ohne Paketidentität",
			scanNoPackageIDsLead:                   "%d Inhaltselemente lieferten keine Paketidentität. Die vollständige Liste für die Nachvollziehbarkeit steht unten:",
			noScanNoPackageIDs:                     "In diesem Lauf wurden keine Inhaltselemente ohne Paketidentität festgestellt.",
			deliveryPath:                           "Lieferpfad",
			status:                                 "Status",
			tool:                                   "Werkzeug",
			duration:                               "Dauer",
			suppliedBy:                             "Durch Benutzer angegeben",
			derived:                                "Automatisch abgeleitet",
			residualRiskText:                       "Die folgenden Punkte beschreiben Abdeckungsgrenzen und Auslegungsrisiken für die Verwendung des SBOM in der Schwachstellenbewertung:",
			residualRiskProfileLead:                "Das Verfahren ist manifest- und metadatenbasiert. Besonders belastbar sind Formate mit expliziten Paketmetadaten, etwa RPM, DEB oder Java-Archive mit Maven- bzw. Manifest-Metadaten. Schwächer ist die Abdeckung bei bloßen Dateien, gebündelten Kopien ohne Manifest und Windows-Binärdateien mit knappen oder fehlenden Versionsressourcen.",
			residualRiskAbsenceHint:                "Das Fehlen einer Komponente im SBOM ist kein Beleg dafür, dass der zugrunde liegende Code nicht vorhanden ist; es bedeutet nur, dass dafür keine verwertbare Paketmetadaten-Evidenz beobachtet wurde.",
			residualRiskPURLCoverage:               "%d von %d indexierten Komponenten-Vorkommen tragen eine PURL. %d indexierte Vorkommen haben keine PURL und lassen sich deshalb typischerweise nur eingeschränkt oder gar nicht automatisch gegen CVE-Datenbanken korrelieren.",
			residualRiskEvidenceCoverage:           "%d indexierte Vorkommen haben einen konkreten Evidenzpfad. %d stützen sich nur auf einen allgemeinen Evidenzhinweis, und %d haben keine zusätzliche Evidenzangabe über den Komponenten-Datensatz hinaus.",
			residualRiskNoComponentTasks:           "%d von %d untersuchten Inhaltselementen lieferten keine Paketidentität. Das bedeutet: Der Inhalt wurde gesehen, aber es war keine verwertbare Paketmetadaten-Evidenz vorhanden. Beispiele: %s.",
			residualRiskFileArtifactCoverage:       "Syft erzeugte außerdem %d dateibezogene Rohfunde ohne belastbare Paketkoordinaten. Diese Einträge dokumentieren beobachtete Dateien, eignen sich aber nicht als eigenständige Grundlage für CVE-Abgleiche und werden deshalb nicht als Paketbefund geführt.",
			residualRiskExtensionFilter:            "Der Dateiendungsfilter schloss %d Dateien von der Untersuchung aus; diese Dateien sind nicht im Komponentenbestand enthalten. Details: %s.",
			residualRiskExtractionGap:              "%d Extraktionsknoten konnten nicht vollständig verarbeitet werden. Beispiele: %s.",
			residualRiskToolGap:                    "%d Extraktionsknoten erfordern nicht verfügbare Hilfswerkzeuge. Beispiele: %s.",
			residualRiskScanGap:                    "%d Inhaltselemente konnten nicht gescannt werden. Beispiele: %s.",
			residualRiskMoreDetails:                "Hintergrund zur Zuverlässigkeit der Paketerkennung: %s.",
			noPolicyDecisions:                      "Keine Richtlinienentscheidungen protokolliert.",
			noProcessingIssues:                     "Keine Verarbeitungsfehler protokolliert.",
			summaryLead:                            "Dieser Bericht dokumentiert die in der Lieferung aufgefundenen Softwarepakete, ihre Fundorte und eventuelle Schwachstellenbefunde. Jedes Paket (identifiziert durch Name und Version) kann an mehreren Stellen innerhalb der Lieferung vorkommen; jedes Vorkommen ist mit einer eindeutigen Komponenten-ID erfasst und über seinen Belegpfad bis zum konkreten Lieferpfad rückverfolgbar. Schwachstellenbefunde werden über PURL oder andere Merkmale mit den Paketen verknüpft.",
			summaryLeadNoVuln:                      "Dieser Bericht dokumentiert die in der Lieferung aufgefundenen Softwarepakete und ihre Fundorte. Jedes Paket (identifiziert durch Name und Version) kann an mehreren Stellen innerhalb der Lieferung vorkommen; jedes Vorkommen ist mit einer eindeutigen Komponenten-ID erfasst und über seinen Belegpfad bis zum konkreten Lieferpfad rückverfolgbar.",
			vulnEnrichmentNotRequested:             "Schwachstellenanreicherung: nicht angefordert",
			vulnEnrichmentStateTemplate:            "Schwachstellenanreicherungsstatus: `%s`",
			vulnGrypeVersionTemplate:               "Grype-Version: `%s`",
			vulnGrypeDBTemplate:                    "Grype-Datenbank: schema=`%s` built=`%s` updated=`%s`",
			vulnEnrichmentIssuesTemplate:           "Schwachstellenanreicherungsprobleme: %d",
			vulnFindingsTemplate:                   "Schwachstellenbefunde: treffer=%d eindeutige-schwachstellen=%d betroffene-komponenten=%d",
			vulnNoMatchedFindings:                  "Schwachstellenbefunde: keine zugeordneten Schwachstellen",
			findingVulnMatchesTemplate:             "%d Schwachstellentreffer in %d Paketen (%d eindeutige CVEs) — siehe %s.",
			findingVulnNoMatches:                   "Schwachstellenscan abgeschlossen — keine Treffer.",
			findingDeliveryCompositionTemplate:     "Das Lieferpaket bestand aus %d Archiven mit insgesamt %d enthaltenen Dateien. Darin wurden %d verschiedene Softwarekomponenten identifiziert. Diese stammen aus insgesamt %d identifizierten Softwarepaketen.",
			findingExtractionStatusSuccessTemplate: "Es konnten alle Dateien extrahiert werden.",
			findingExtractionStatusFailureTemplate: "%d Dateien konnten nicht extrahiert werden.",
			reportHeaderGeneratorVersionTemplate:   "**Bericht generiert:** %s | **extract-sbom-Version:** %s (auf Basis von %s)",
			reportHeaderToolsLabel:                 "**Tools:**",
			vulnSummaryHeading:                     "Schwachstellenübersicht (grype-inspirierte Ansicht):",
			vulnTableName:                          "Name",
			vulnTableInstalled:                     "Installiert",
			vulnTableFixedIn:                       "Behoben in",
			vulnTableVulnerability:                 "Schwachstelle",
			vulnTableSeverity:                      "Schweregrad",
			vulnTableEPSS:                          "EPSS",
			vulnTableRisk:                          "Risiko",
			vulnTableKEV:                           "KEV",
			vulnStatusFoundTemplate:                "Schwachstellenstatus: `found` (%d)",
			vulnStatusNotAssessableUnavailable:     "Schwachstellenstatus: `not-assessable` (Anreicherung nicht verfügbar oder unvollständig)",
			vulnStatusNotAssessableNoID:            "Schwachstellenstatus: `not-assessable` (keine PURL/CPE)",
			vulnStatusNone:                         "Schwachstellenstatus: `none`",
			vulnDetailSourceTemplate:               "Quelle: %s",
			vulnDetailFixTemplate:                  "Behebung: status=`%s` versionen=`%s`",
			vulnDetailCVSSTemplate:                 "CVSS: version=`%s` score=`%s` vector=`%s`",
			vulnDetailCVSSNone:                     "CVSS: version=`-` score=`-` vector=`-`",
			vulnDetailDescriptionTemplate:          "Beschreibung: %s",
			vulnDetailDescriptionNone:              "Beschreibung: -",
			vulnDetailEPSSTemplate:                 "EPSS: %s",
			vulnDetailReferenceTemplate:            "Referenz: %s",
			vulnKEVYes:                             "ja",
			vulnKEVNo:                              "nein",
			methodLead:                             "Hier steht nur die Kurzfassung. Die vollständige operator-orientierte Erläuterung steht in SCAN_APPROACH.md auf GitHub.",
			methodBulletTwoPhases:                  "Die Lieferung wird zunächst entpackt und in konkrete Artefakte gegliedert. Anschließend werden Paketmetadaten aus extrahierten Verzeichnisbäumen und aus direkt lesbaren Paketdateien gesammelt.",
			methodBulletEvidence:                   "Paketidentitäten werden nur dann behauptet, wenn dafür beobachtbare Evidenz vorliegt, etwa Paketmanifeste, JAR-Metadaten, MSI-Property-Tabellen oder Binär-Metadaten.",
			methodBulletDedup:                      "Deduplikation ist nachvollziehbar: schwache Platzhalter und wiederholte PURLs werden entfernt, aber die überlebende Komponente behält die konkreten Blatt-Delivery- und Evidence-Pfade.",
			methodBulletTrust:                      "Der Lauf ist deterministisch: Die Eingabedatei ist gehasht, die Lieferpfade sind stabil und Fehler oder Abdeckungsgrenzen werden explizit protokolliert statt verborgen.",
			methodMoreDetails:                      "Vertiefung in SCAN_APPROACH.md:",
			appendixLead:                           "Die folgenden Abschnitte enthalten die vollständige Rohspur für Stichproben, vertiefte technische Prüfung und Belegexport. Sie sind bewusst ausführlich und werden typischerweise erst benötigt, wenn die relevante Objekt-ID oder der relevante Lieferpfad bereits feststeht.",
			summaryKeyFindingsSection:              "Wesentliche Befunde",
			summaryAnalysisSection:                 "Analyseergebnis",
			summaryVulnSection:                     "Schwachstellenübersicht",
			endOfReport:                            "Ende des Berichts.",
			policyDecisionAt:                       "bei",
			linkTwoPhases:                          "Zwei Phasen",
			linkScanDetail:                         "Scan-Details",
			linkFinalSBOMBuild:                     "Finaler SBOM-Aufbau",
			linkDeduplication:                      "Deduplikation",
			linkPackageDetectionReliability:        "Zuverlaessigkeit der Paketerkennung",
			summaryAnalysisProseTemplate:           "extract-sbom hat %d Dateien und Archive innerhalb der Lieferung untersucht. Nach Deduplikation und Normalisierung ergab die Untersuchung %d eindeutige Paketvorkommen im Komponentenindex. Davon tragen %d eine PURL (Package-URL), die automatisierte CVE-Datenbankabfragen ermöglicht; %d tragen keine PURL, können aber dennoch über namensbasierte oder andere Merkmale in Schwachstellenbefunden auftauchen.",
			summaryAnalysisMethodRef:               "Die Prüfmethode, Deduplikationslogik und Abdeckungsgrenzen werden in %s erläutert.",
			findingToolMissingTemplate:             "%d Dateien oder Archive konnten nicht untersucht werden, weil ein benötigtes Hilfswerkzeug nicht verfügbar war. Beispiele: %s.",
			findingExtractionGapTemplate:           "%d Dateien oder Archive konnten nicht geöffnet oder verarbeitet werden (fehlgeschlagen oder sicherheitsblockiert). Beispiele: %s.",
			findingScanFailedTemplate:              "Die Paketidentifikation schlug für %d Inhaltselemente fehl. Beispiele: %s.",
			findingPURLCoverageTemplate:            "%d von %d indexierten Paketvorkommen [tragen eine PURL](#%s); [%d nicht](#%s). Eine PURL ermöglicht automatisierten CVE-Abgleich; Pakete ohne PURL können dennoch über Namensabgleich in Befunden auftauchen.",
			findingNoPackageIdentityTemplate:       "%d Inhaltselemente enthielten keine identifizierbaren Softwarepakete (siehe %s). Beispiele: %s.",
			findingNoCriticalLimitations:           "Keine kritischen Verarbeitungsgrenzen in diesem Lauf erkannt.",
			findingPolicyDecisionsTemplate:         "%d Richtlinienentscheidungen wurden in diesem Lauf ausgelöst. Details: %s.",
			findingProcessingIssuesTemplate:        "%d Verarbeitungsfehler auf Pipeline-Ebene wurden erfasst. Details: %s.",
			processingPipelineLabel:                "pipeline",
			processingExtractionFailedLabel:        "extraktion-fehlgeschlagen",
			processingSecurityBlockedLabel:         "extraktion-sicherheitsblockiert",
			processingToolMissingLabel:             "extraktion-werkzeug-fehlt",
			processingScanErrorsLabel:              "scan-fehler",
			processingSourceHeader:                 "Quelle",
			processingLocationHeader:               "Ort",
			processingClassHeader:                  "Klasse",
			processingStatusHeader:                 "Status",
			processingDetectedHeader:               "Erkannt",
			processingToolHeader:                   "Werkzeug",
			processingArchiveTypeHeader:            "Archiv-Type",
			processingArchiveMethodHeader:          "Archiv-Method",
			processingEncryptedHeader:              "Verschluesselt",
			processingPhysicalSizeHeader:           "Phys. Groesse",
			processingDetailHeader:                 "Detail",
			additionalEntriesOmittedTemplate:       "%d zusaetzliche Eintraege ausgelassen",
			noneValue:                              "keine",
			reasonLabel:                            "Grund",
			countLabel:                             "Anzahl",
			suppressionOperationalFS:               "Operative Bedeutung: Dies sind dateibasierte Syft-Eintraege und keine beibehaltenen Paketbefunde. Fuer Vulnerability-Triage ist hier normalerweise keine Aktion noetig. Sie werden nur fuer auditierbare Normalisierung dokumentiert.",
			suppressionOperationalFSFollowUp:       "Wenn fuer dieselbe Datei eine Paketidentitaet existiert, ist der relevante Eintrag die ueberlebende Komponente im Komponentenindex.",
			suppressionOperationalLowValue:         "Operative Bedeutung: Diese Roh-Dateieintraege hatten keine PURL, keine Version und keine identifizierenden Cataloger-Metadaten. Sie eignen sich nicht fuer paketbasierte CVE-Korrelation und werden daher aus der SBOM-Paketsicht ausgeschlossen.",
			suppressionOperationalWeakDup:          "Operative Bedeutung: Am selben Liefer-/Evidenz-Ort existierte bereits ein staerkerer Paketeintrag. Der schwaechere Platzhalter wurde entfernt, damit die finale SBOM die besser zurechenbare Identitaet behaelt.",
			suppressionOperationalPURLDup:          "Operative Bedeutung: Mehrere Rohbeobachtungen beschrieben dieselbe Paketidentitaet. Eine Repraesentation blieb erhalten; die ueberlebende Komponente im Komponentenindex traegt die beibehaltenen blattnahen Liefer- und Evidenzpfade. Diese Tabelle dient nur der Audit-Nachvollziehbarkeit der Zusammenfuehrung.",
			suppressionTableDeliveryPath:           "Lieferpfad",
			suppressionTableComponentName:          "Unterdrueckter Komponentenname",
			suppressionTableSuppressedBy:           "Unterdrueckt durch",
			extractionSandboxLabel:                 "sandbox",

			componentNormalizationSection:  "Komponentennormalisierung",
			componentNormalizationLead:     "Alle Komponenten, die aus dem SBOM entfernt wurden, sind hier mit Begründung aufgeführt. Dies gewährleistet die vollständige Nachverfolgbarkeit zwischen SBOM und Prüfbericht.",
			noSuppressions:                 "Keine Komponenten entfernt.",
			suppressionReasonFSArtifact:    "FS-Cataloger-Artefakt",
			suppressionReasonLowValueFile:  "Datei ohne Identifikationsmerkmale",
			suppressionReasonWeakDuplicate: "Schwaches Duplikat",
			suppressionReasonPURLDuplicate: "PURL-Duplikat",
			suppressionReplacedBy:          "Ersetzt durch",

			extensionFilterSection:              "Dateiendungsfilter",
			extensionFilterLead:                 "Die folgenden Dateiendungen sind so konfiguriert, dass sie von der rekursiven Extraktion und Syft-Analyse ausgeschlossen werden. Dateien, die diesen Endungen entsprechen, werden im Extraktionsprotokoll nicht aufgeführt und nicht auf Softwarekomponenten untersucht. Die vollständige Abdeckbarkeit der SBOM ist für gefilterte Dateien nicht gewährleistet.",
			extensionFilterExtensionsLabel:      "Konfigurierter Dateiendungsfilter",
			extensionFilterSkippedLabel:         "Durch diesen Filter ausgeschlossene Dateien",
			noExtensionFilteredFiles:            "In diesem Durchlauf wurden keine Dateien durch den Dateiendungsfilter ausgeschlossen.",
			componentIndexWithPURLSubsection:    "Komponenten mit PURL",
			componentIndexWithoutPURLSubsection: "Komponenten ohne PURL",
			occurrencesLabel:                    "Vorkommen",
			purlsLabel:                          "PURL",
			componentIDLabel:                    "Komponenten-ID",
			suppressedByNoIndexedMatch:          "durch Normalisierungsregel entfernt; für diesen Lieferpfad existiert keine überlebende Paketkomponente (siehe [Komponentenindex](#component-occurrence-index))",
			suppressedByAmbiguousIndexedMatch:   "durch Normalisierungsregel entfernt; mehrere überlebende Paketkomponenten passen zu diesem Lieferpfad, daher erfolgt keine unsichere 1:1-Zuordnung (siehe [Komponentenindex](#component-occurrence-index))",
			suppressedByReplacementNotIndexed:   "durch Normalisierungsregel ersetzt; Ziel ist ein nicht indizierter Struktur-/Container-Eintrag (siehe [Extraktionsprotokoll](#extraction-log))",
		}
	default:
		return translations{
			title:                                  "extract-sbom Audit Report",
			inputSection:                           "Input File",
			configSection:                          "Configuration",
			rootMetadataSection:                    "Root SBOM Metadata",
			sandboxSection:                         "Sandbox Configuration",
			extractionSection:                      "Extraction Log",
			scanSection:                            "Package Scan Log",
			policySection:                          "Policy Decisions",
			summarySection:                         "Summary",
			residualRiskSection:                    "Residual Risk and Limitations",
			processingIssuesSection:                "Processing Errors",
			field:                                  "Field",
			value:                                  "Value",
			source:                                 "Source",
			setting:                                "Setting",
			filename:                               "Filename",
			filesize:                               "File size",
			unitBytes:                              "bytes",
			skipExtensions:                         "skip-extensions",
			nameLabel:                              "Name",
			manufacturerLabel:                      "Manufacturer",
			deliveryDateLabel:                      "Delivery Date",
			policyMode:                             "Policy mode",
			interpretMode:                          "Interpretation mode",
			language:                               "Language",
			maxDepth:                               "Max depth",
			maxFiles:                               "Max files",
			maxTotalSize:                           "Max total size",
			maxEntrySize:                           "Max entry size",
			maxRatio:                               "Max ratio",
			timeout:                                "Timeout",
			progressLevel:                          "Progress",
			generator:                              "extract-sbom build",
			sandboxName:                            "Sandbox",
			sandboxAvail:                           "Available",
			unsafeWarning:                          "WARNING",
			unsafeActive:                           "Unsafe mode active — no sandbox isolation",
			tableOfContentsSection:                 "Table of Contents",
			methodOverviewSection:                  "Method At A Glance",
			appendixSection:                        "Appendix",
			componentIndexSection:                  "Component Occurrence Index",
			componentIndexLead:                     "Entries are grouped by package identity (name+version). Under each package, concrete component occurrences are listed (object ID = SBOM bom-ref and Grype artifact.id) with their delivery and evidence paths.",
			noIndexedComponents:                    "No component occurrences indexed.",
			objectID:                               "Object ID",
			packageName:                            "Package",
			version:                                "Version",
			purl:                                   "PURL",
			evidencePath:                           "Evidence path",
			foundBy:                                "Found by",
			noEvidenceRecorded:                     "no component-specific evidence recorded",
			scanError:                              "Error:",
			componentsFound:                        "components found",
			noComponents:                           "no components found",
			scanSectionLead:                        "This is a per-item package scan log. Evidence lines in this section are item-level observations and may cover several final components. The authoritative per-component evidence statements are in the Component Occurrence Index.",
			scanTaskEvidenceLabel:                  "evidence-path",
			scanNoPackageIDsSection:                "Content Items Without Package Identities",
			scanNoPackageIDsLead:                   "%d content items produced no package identities. The complete list for audit traceability is shown below:",
			noScanNoPackageIDs:                     "No content items without package identities were observed in this run.",
			deliveryPath:                           "Delivery path",
			status:                                 "Status",
			tool:                                   "Tool",
			duration:                               "Duration",
			suppliedBy:                             "User-supplied",
			derived:                                "Auto-derived",
			residualRiskText:                       "The following points describe coverage boundaries and interpretation risks that matter when the SBOM is used for vulnerability assessment:",
			residualRiskProfileLead:                "The method is manifest- and metadata-based. Reliability is highest for formats with explicit package metadata, such as RPM, DEB, or Java archives with Maven or manifest metadata. Coverage is weaker for plain files, bundled copies without manifests, and Windows binaries with sparse or missing VERSIONINFO.",
			residualRiskAbsenceHint:                "The absence of a component from the SBOM is not proof that the underlying code is absent; it means only that no usable package-metadata evidence was observed for it.",
			residualRiskPURLCoverage:               "%d of %d indexed component occurrences carry a PURL. %d indexed occurrences do not carry a PURL and therefore usually correlate poorly or not at all with vulnerability databases.",
			residualRiskEvidenceCoverage:           "%d indexed occurrences carry a concrete evidence path. %d rely only on a generic evidence-source statement, and %d have no additional evidence detail beyond the component record.",
			residualRiskNoComponentTasks:           "%d of %d scanned content items produced no package identities. This means the content was seen, but no usable package metadata was present. Examples: %s.",
			residualRiskFileArtifactCoverage:       "Syft also emitted %d file-level records without actionable package coordinates. These records show that files were observed, but they do not by themselves support CVE matching and are therefore not listed as package findings.",
			residualRiskExtensionFilter:            "The extension filter excluded %d files from examination; these files are not reflected in the component inventory. Details: %s.",
			residualRiskExtractionGap:              "%d extraction nodes could not be processed completely. Examples: %s.",
			residualRiskToolGap:                    "%d extraction nodes require unavailable helper tools. Examples: %s.",
			residualRiskScanGap:                    "%d content items could not be scanned. Examples: %s.",
			residualRiskMoreDetails:                "Background on package-detection reliability: %s.",
			noPolicyDecisions:                      "No policy decisions recorded.",
			noProcessingIssues:                     "No processing issues recorded.",
			summaryLead:                            "This report documents the software packages found within the delivery, their locations, and any known vulnerability findings. Each identified package (name + version) may occur at multiple locations inside the delivery; each occurrence is recorded with a unique Component-ID and is traceable through its evidence path back to the exact delivery path. Vulnerability findings link back to packages via PURL or other identifiers.",
			summaryLeadNoVuln:                      "This report documents the software packages found within the delivery and their locations. Each identified package (name + version) may occur at multiple locations inside the delivery; each occurrence is recorded with a unique Component-ID and is traceable through its evidence path back to the exact delivery path.",
			vulnEnrichmentNotRequested:             "Vulnerability enrichment: not requested",
			vulnEnrichmentStateTemplate:            "Vulnerability enrichment state: `%s`",
			vulnGrypeVersionTemplate:               "Grype version: `%s`",
			vulnGrypeDBTemplate:                    "Grype DB: schema=`%s` built=`%s` updated=`%s`",
			vulnEnrichmentIssuesTemplate:           "Vulnerability enrichment issues: %d",
			vulnFindingsTemplate:                   "Vulnerability findings: matches=%d unique-vulnerabilities=%d affected-components=%d",
			vulnNoMatchedFindings:                  "Vulnerability findings: no matched vulnerabilities",
			findingVulnMatchesTemplate:             "%d vulnerability matches in %d packages (%d unique CVEs) — see %s.",
			findingVulnNoMatches:                   "Vulnerability scan complete — no matched findings.",
			findingDeliveryCompositionTemplate:     "The delivery package contained %d archives (with %d files in total). Within this, %d distinct software components were identified. These stem from a total of %d identified software packages.",
			findingExtractionStatusSuccessTemplate: "All files were successfully extracted.",
			findingExtractionStatusFailureTemplate: "%d files could not be extracted.",
			reportHeaderGeneratorVersionTemplate:   "**Report generated:** %s | **extract-sbom version:** %s (based on %s)",
			reportHeaderToolsLabel:                 "**Tools:**",
			vulnSummaryHeading:                     "Vulnerability summary (grype-inspired view):",
			vulnTableName:                          "Name",
			vulnTableInstalled:                     "Installed",
			vulnTableFixedIn:                       "Fixed In",
			vulnTableVulnerability:                 "Vulnerability",
			vulnTableSeverity:                      "Severity",
			vulnTableEPSS:                          "EPSS",
			vulnTableRisk:                          "Risk",
			vulnTableKEV:                           "KEV",
			vulnStatusFoundTemplate:                "Vulnerability status: `found` (%d)",
			vulnStatusNotAssessableUnavailable:     "Vulnerability status: `not-assessable` (enrichment unavailable or incomplete)",
			vulnStatusNotAssessableNoID:            "Vulnerability status: `not-assessable` (no PURL/CPE)",
			vulnStatusNone:                         "Vulnerability status: `none`",
			vulnDetailSourceTemplate:               "Source: %s",
			vulnDetailFixTemplate:                  "Fix: state=`%s` versions=`%s`",
			vulnDetailCVSSTemplate:                 "CVSS: version=`%s` score=`%s` vector=`%s`",
			vulnDetailCVSSNone:                     "CVSS: version=`-` score=`-` vector=`-`",
			vulnDetailDescriptionTemplate:          "Description: %s",
			vulnDetailDescriptionNone:              "Description: -",
			vulnDetailEPSSTemplate:                 "EPSS: %s",
			vulnDetailReferenceTemplate:            "Reference: %s",
			vulnKEVYes:                             "yes",
			vulnKEVNo:                              "no",
			methodLead:                             "This section is the compressed version. The full operator-oriented explanation lives in SCAN_APPROACH.md on GitHub.",
			methodBulletTwoPhases:                  "The delivery is first unpacked and classified into concrete artifacts. Package metadata is then collected from extracted directory trees and from directly readable package files.",
			methodBulletEvidence:                   "A package identity is asserted only when observable evidence exists, such as package manifests, JAR metadata, MSI property tables, or binary metadata.",
			methodBulletDedup:                      "Deduplication is traceable: weak placeholders and repeated PURLs are removed, but the surviving component keeps the concrete leaf-most delivery and evidence paths.",
			methodBulletTrust:                      "The run is deterministic: the input file is hash-pinned, logical delivery paths are stable, and errors or coverage limits are recorded instead of hidden.",
			methodMoreDetails:                      "Deep links into SCAN_APPROACH.md:",
			appendixLead:                           "The sections below preserve the detailed audit trail for spot checks, deeper technical review, and evidence export. They are intentionally exhaustive and are usually only needed once the relevant object id or delivery path is already known.",
			summaryKeyFindingsSection:              "Key Findings",
			summaryAnalysisSection:                 "Analysis Overview",
			summaryVulnSection:                     "Vulnerability Summary",
			endOfReport:                            "End of report.",
			policyDecisionAt:                       "at",
			linkTwoPhases:                          "Two phases",
			linkScanDetail:                         "Scan detail",
			linkFinalSBOMBuild:                     "Final SBOM build",
			linkDeduplication:                      "Deduplication",
			linkPackageDetectionReliability:        "Package Detection Reliability",
			summaryAnalysisProseTemplate:           "extract-sbom examined %d files and archives within the delivery. After deduplication and normalization, the inspection produced %d distinct package occurrences in the Component Occurrence Index. Of these, %d carry a PURL (package URL) that enables automated CVE database queries; %d do not carry a PURL, though these packages may still yield vulnerability findings via name-based or other matching.",
			summaryAnalysisMethodRef:               "The inspection approach, deduplication logic, and coverage boundaries are explained in %s.",
			findingToolMissingTemplate:             "%d files or archives could not be examined because a required helper tool was unavailable. Examples: %s.",
			findingExtractionGapTemplate:           "%d files or archives could not be opened or processed (failed or security-blocked). Examples: %s.",
			findingScanFailedTemplate:              "Package identification failed for %d content items. Examples: %s.",
			findingPURLCoverageTemplate:            "%d of %d package occurrences [carry a PURL](#%s); [%d do not](#%s). A PURL enables automated CVE database lookup; packages without a PURL may still yield findings via name-based matching.",
			findingNoPackageIdentityTemplate:       "%d content items contained no identifiable software packages (see %s). Examples: %s.",
			findingNoCriticalLimitations:           "No critical processing limitations detected in this run.",
			findingPolicyDecisionsTemplate:         "%d policy decisions were triggered during this run. Details: %s.",
			findingProcessingIssuesTemplate:        "%d pipeline processing issues were recorded. Details: %s.",
			processingPipelineLabel:                "pipeline",
			processingExtractionFailedLabel:        "extraction-failed",
			processingSecurityBlockedLabel:         "extraction-security-blocked",
			processingToolMissingLabel:             "extraction-tool-missing",
			processingScanErrorsLabel:              "scan-errors",
			processingSourceHeader:                 "Source",
			processingLocationHeader:               "Location",
			processingClassHeader:                  "Class",
			processingStatusHeader:                 "Status",
			processingDetectedHeader:               "Detected",
			processingToolHeader:                   "Tool",
			processingArchiveTypeHeader:            "Archive Type",
			processingArchiveMethodHeader:          "Archive Method",
			processingEncryptedHeader:              "Encrypted",
			processingPhysicalSizeHeader:           "Physical Size",
			processingDetailHeader:                 "Detail",
			additionalEntriesOmittedTemplate:       "%d additional entries omitted",
			noneValue:                              "none",
			reasonLabel:                            "Reason",
			countLabel:                             "Count",
			suppressionOperationalFS:               "Operational meaning: these are file-level Syft records, not retained package findings. They normally require no action during vulnerability triage. They are listed here only so the normalization step remains auditable.",
			suppressionOperationalFSFollowUp:       "When a package identity exists for the same file, the actionable record is the surviving component in the Component Occurrence Index.",
			suppressionOperationalLowValue:         "Operational meaning: these raw file records had no PURL, no version, and no identifying cataloger metadata. They do not support package-level CVE correlation and are therefore excluded from the SBOM package view.",
			suppressionOperationalWeakDup:          "Operational meaning: at the same delivery/evidence locus a stronger package record existed. The weaker placeholder was removed so that the final SBOM keeps the more attributable identity.",
			suppressionOperationalPURLDup:          "Operational meaning: several raw observations described the same package identity. One representative was kept, and the surviving component in the Component Occurrence Index carries the retained leaf-most delivery and evidence paths. Use this table only when you need to audit why duplicate raw observations collapsed into one package component.",
			suppressionTableDeliveryPath:           "Delivery path",
			suppressionTableComponentName:          "Suppressed component name",
			suppressionTableSuppressedBy:           "Suppressed by",
			extractionSandboxLabel:                 "sandbox",

			componentNormalizationSection:  "Component Normalization",
			componentNormalizationLead:     "Every component removed from the SBOM during normalization or deduplication is listed here with its reason. This ensures full traceability between the SBOM and the audit report.",
			noSuppressions:                 "No components removed.",
			suppressionReasonFSArtifact:    "FS-cataloger artifact",
			suppressionReasonLowValueFile:  "File with no identification metadata",
			suppressionReasonWeakDuplicate: "Weak duplicate",
			suppressionReasonPURLDuplicate: "PURL duplicate",
			suppressionReplacedBy:          "Replaced by",

			extensionFilterSection:              "Extension Filter",
			extensionFilterLead:                 "The following file extensions are configured to be excluded from recursive extraction and Syft scanning. Files matching these extensions are not examined for software components and are therefore not reflected in the component inventory. Full SBOM coverage cannot be guaranteed for filtered file types.",
			extensionFilterExtensionsLabel:      "Configured extension filter",
			extensionFilterSkippedLabel:         "Files excluded by this filter",
			noExtensionFilteredFiles:            "No files were excluded by the extension filter in this run.",
			componentIndexWithPURLSubsection:    "Components with PURL",
			componentIndexWithoutPURLSubsection: "Components without PURL",
			occurrencesLabel:                    "Occurrences",
			purlsLabel:                          "PURL",
			componentIDLabel:                    "Component-ID",
			suppressedByNoIndexedMatch:          "removed by normalization rule; no surviving package component exists for this delivery path (see [Component Occurrence Index](#component-occurrence-index))",
			suppressedByAmbiguousIndexedMatch:   "removed by normalization rule; multiple surviving package components match this delivery path, so no unsafe 1:1 assignment is made (see [Component Occurrence Index](#component-occurrence-index))",
			suppressedByReplacementNotIndexed:   "replaced by normalization rule; target is a non-indexed structural/container entry (see [Extraction Log](#extraction-log))",
		}
	}
}
