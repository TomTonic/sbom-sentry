package report

// translations contains all localized report labels and prose snippets used
// by human-report generation.
type translations struct {
	title                             string
	inputSection                      string
	configSection                     string
	rootMetadataSection               string
	sandboxSection                    string
	extractionSection                 string
	scanSection                       string
	scanSectionLead                   string
	scanTaskEvidenceLabel             string
	scanNoPackageIDsSection           string
	scanNoPackageIDsLead              string
	noScanNoPackageIDs                string
	policySection                     string
	summarySection                    string
	residualRiskSection               string
	processingIssuesSection           string
	field                             string
	value                             string
	source                            string
	setting                           string
	filename                          string
	filesize                          string
	unitBytes                         string
	skipExtensions                    string
	nameLabel                         string
	manufacturerLabel                 string
	deliveryDateLabel                 string
	policyMode                        string
	interpretMode                     string
	language                          string
	maxDepth                          string
	maxFiles                          string
	maxTotalSize                      string
	maxEntrySize                      string
	maxRatio                          string
	timeout                           string
	progressLevel                     string
	generator                         string
	sandboxName                       string
	sandboxAvail                      string
	unsafeWarning                     string
	unsafeActive                      string
	tableOfContentsSection            string
	howToUseSection                   string
	methodOverviewSection             string
	appendixSection                   string
	componentIndexSection             string
	componentIndexLead                string
	noIndexedComponents               string
	objectID                          string
	packageName                       string
	version                           string
	purl                              string
	evidencePath                      string
	foundBy                           string
	noEvidenceRecorded                string
	processingTime                    string
	scanError                         string
	componentsFound                   string
	noComponents                      string
	deliveryPath                      string
	status                            string
	tool                              string
	duration                          string
	suppliedBy                        string
	derived                           string
	residualRiskText                  string
	residualRiskProfileLead           string
	residualRiskAbsenceHint           string
	residualRiskPURLCoverage          string
	residualRiskEvidenceCoverage      string
	residualRiskNoComponentTasks      string
	residualRiskFileArtifactCoverage  string
	residualRiskExtensionFilter       string
	residualRiskExtractionGap         string
	residualRiskToolGap               string
	residualRiskScanGap               string
	residualRiskMoreDetails           string
	noPolicyDecisions                 string
	noProcessingIssues                string
	summaryLead                       string
	summaryAssemblyMath               string
	summaryNextStepTemplate           string
	howToUseLead                      string
	howToUseStep1                     string
	howToUseStep2Template             string
	howToUseStep3                     string
	howToUseStep4Template             string
	methodLead                        string
	methodBulletTwoPhases             string
	methodBulletEvidence              string
	methodBulletDedup                 string
	methodBulletTrust                 string
	methodMoreDetails                 string
	appendixLead                      string
	summaryExtraction                 string
	summaryScan                       string
	summaryComponents                 string
	summaryPolicies                   string
	summaryProcessingIssues           string
	summaryFindings                   string
	endOfReport                       string
	policyDecisionAt                  string
	linkTwoPhases                     string
	linkScanDetail                    string
	linkFinalSBOMBuild                string
	linkDeduplication                 string
	linkPackageDetectionReliability   string
	summaryExtractionStatsTemplate    string
	summaryScanStatsTemplate          string
	summaryComponentsStatsTemplate    string
	summaryPoliciesStatsTemplate      string
	summaryProcessingStatsTemplate    string
	findingToolMissingTemplate        string
	findingExtractionGapTemplate      string
	findingScanFailedTemplate         string
	findingAllScansSuccessfulTemplate string
	findingPURLCoverageTemplate       string
	findingNoPackageIdentityTemplate  string
	findingIndexQualityTemplate       string
	findingNoCriticalLimitations      string
	processingPipelineLabel           string
	processingExtractionFailedLabel   string
	processingSecurityBlockedLabel    string
	processingToolMissingLabel        string
	processingScanErrorsLabel         string
	processingSourceHeader            string
	processingLocationHeader          string
	processingDetailHeader            string
	additionalEntriesOmittedTemplate  string
	noneValue                         string
	reasonLabel                       string
	countLabel                        string
	suppressionOperationalFS          string
	suppressionOperationalFSFollowUp  string
	suppressionOperationalLowValue    string
	suppressionOperationalWeakDup     string
	suppressionOperationalPURLDup     string
	suppressionTableDeliveryPath      string
	suppressionTableComponentName     string
	suppressionTableSuppressedBy      string
	extractionSandboxLabel            string

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
			title:                             "extract-sbom Prüfbericht",
			inputSection:                      "Eingabedatei",
			configSection:                     "Konfiguration",
			rootMetadataSection:               "SBOM Stammdaten",
			sandboxSection:                    "Sandbox-Konfiguration",
			extractionSection:                 "Extraktionsprotokoll",
			scanSection:                       "Scan-Task-Protokoll",
			policySection:                     "Richtlinienentscheidungen",
			summarySection:                    "Zusammenfassung",
			residualRiskSection:               "Restrisiko und Einschränkungen",
			processingIssuesSection:           "Verarbeitungsfehler",
			field:                             "Feld",
			value:                             "Wert",
			source:                            "Quelle",
			setting:                           "Einstellung",
			filename:                          "Dateiname",
			filesize:                          "Dateigröße",
			unitBytes:                         "Bytes",
			skipExtensions:                    "skip-extensions",
			nameLabel:                         "Name",
			manufacturerLabel:                 "Hersteller",
			deliveryDateLabel:                 "Lieferdatum",
			policyMode:                        "Richtlinienmodus",
			interpretMode:                     "Interpretationsmodus",
			language:                          "Sprache",
			maxDepth:                          "Maximale Tiefe",
			maxFiles:                          "Maximale Dateien",
			maxTotalSize:                      "Maximale Gesamtgröße",
			maxEntrySize:                      "Maximale Eintragsgröße",
			maxRatio:                          "Maximales Verhältnis",
			timeout:                           "Zeitlimit",
			progressLevel:                     "Fortschritt",
			generator:                         "extract-sbom Build",
			sandboxName:                       "Sandbox",
			sandboxAvail:                      "Verfügbar",
			unsafeWarning:                     "WARNUNG",
			unsafeActive:                      "Unsicherer Modus aktiv — keine Sandbox-Isolation",
			tableOfContentsSection:            "Inhaltsverzeichnis",
			howToUseSection:                   "So benutzt man diesen Bericht",
			methodOverviewSection:             "Verfahren im Kurzüberblick",
			appendixSection:                   "Anhang",
			componentIndexSection:             "Komponentenindex",
			componentIndexLead:                "Die Einträge sind nach Lieferpfad sortiert. Die Objekt-ID entspricht der bom-ref im SBOM und der artifact.id in Grype. `Delivery path` zeigt, wo die Komponente in der Lieferdatei vorkommt. `Evidence path` zeigt die konkrete Datei oder Metadatenquelle, auf der die Identifikation beruht. Wenn mehrere Delivery Paths unter einer Objekt-ID stehen, wurden identische PURLs bewusst zusammengeführt und alle konkreten Blattpfade beibehalten.",
			noIndexedComponents:               "Keine Komponenten-Vorkommen indexiert.",
			objectID:                          "Objekt-ID",
			packageName:                       "Paket",
			version:                           "Version",
			purl:                              "PURL",
			evidencePath:                      "Belegpfad",
			foundBy:                           "Erkannt durch",
			noEvidenceRecorded:                "kein komponentenspezifischer Beleg erfasst",
			processingTime:                    "Verarbeitungszeit",
			scanError:                         "Fehler:",
			componentsFound:                   "Komponenten gefunden",
			noComponents:                      "keine Komponenten gefunden",
			scanSectionLead:                   "Dies ist das Protokoll der einzelnen Scan-Aufgaben. Die hier aufgeführten Evidenzpfade sind task-bezogene Beobachtungen und können mehrere finale Komponenten abdecken. Die maßgebliche komponentenspezifische Evidenz steht im Komponentenindex.",
			scanTaskEvidenceLabel:             "evidence-path",
			scanNoPackageIDsSection:           "Scan-Aufgaben ohne Paketidentität",
			scanNoPackageIDsLead:              "%d erfolgreiche Scan-Aufgaben lieferten keine Paketidentität. Die vollständige Liste für die Nachvollziehbarkeit steht unten:",
			noScanNoPackageIDs:                "In diesem Lauf gab es keine Scan-Aufgaben ohne Paketidentität.",
			deliveryPath:                      "Lieferpfad",
			status:                            "Status",
			tool:                              "Werkzeug",
			duration:                          "Dauer",
			suppliedBy:                        "Durch Benutzer angegeben",
			derived:                           "Automatisch abgeleitet",
			residualRiskText:                  "Die folgenden Punkte beschreiben Abdeckungsgrenzen und Auslegungsrisiken für die Verwendung des SBOM in der Schwachstellenbewertung:",
			residualRiskProfileLead:           "Das Verfahren ist manifest- und metadatenbasiert. Besonders belastbar sind Formate mit expliziten Paketmetadaten, etwa RPM, DEB oder Java-Archive mit Maven- bzw. Manifest-Metadaten. Schwächer ist die Abdeckung bei bloßen Dateien, gebündelten Kopien ohne Manifest und Windows-Binärdateien mit knappen oder fehlenden Versionsressourcen.",
			residualRiskAbsenceHint:           "Das Fehlen einer Komponente im SBOM ist kein Beleg dafür, dass der zugrunde liegende Code nicht vorhanden ist; es bedeutet nur, dass dafür keine verwertbare Paketmetadaten-Evidenz beobachtet wurde.",
			residualRiskPURLCoverage:          "%d von %d indexierten Komponenten-Vorkommen tragen eine PURL. %d indexierte Vorkommen haben keine PURL und lassen sich deshalb typischerweise nur eingeschränkt oder gar nicht automatisch gegen CVE-Datenbanken korrelieren.",
			residualRiskEvidenceCoverage:      "%d indexierte Vorkommen haben einen konkreten Evidenzpfad. %d stützen sich nur auf einen allgemeinen Evidenzhinweis, und %d haben keine zusätzliche Evidenzangabe über den Komponenten-Datensatz hinaus.",
			residualRiskNoComponentTasks:      "%d von %d erfolgreichen Scan-Aufgaben lieferten keine Paketidentität. Das bedeutet: Der Inhalt wurde gesehen, aber es war keine verwertbare Paketmetadaten-Evidenz vorhanden. Beispielaufgaben: %s.",
			residualRiskFileArtifactCoverage:  "Syft erzeugte außerdem %d dateibezogene Rohfunde ohne belastbare Paketkoordinaten. Diese Einträge dokumentieren beobachtete Dateien, eignen sich aber nicht als eigenständige Grundlage für CVE-Abgleiche und werden deshalb nicht als Paketbefund geführt.",
			residualRiskExtensionFilter:       "Der Dateiendungsfilter schloss %d Dateien von der Untersuchung aus; diese Dateien sind nicht im Komponentenbestand enthalten. Details: %s.",
			residualRiskExtractionGap:         "%d Extraktionsknoten konnten nicht vollständig verarbeitet werden. Beispiele: %s.",
			residualRiskToolGap:               "%d Extraktionsknoten erfordern nicht verfügbare Hilfswerkzeuge. Beispiele: %s.",
			residualRiskScanGap:               "%d Scan-Aufgaben schlugen fehl. Beispiele: %s.",
			residualRiskMoreDetails:           "Hintergrund zur Zuverlässigkeit der Paketerkennung: %s.",
			noPolicyDecisions:                 "Keine Richtlinienentscheidungen protokolliert.",
			noProcessingIssues:                "Keine Verarbeitungsfehler protokolliert.",
			summaryLead:                       "Dieser Bericht dokumentiert die beobachteten Paketbefunde, ihre Nachverfolgbarkeit und die Verarbeitungsgrenzen eines einzelnen Prüfungsdurchlaufs über die gelieferte Datei. Er soll die technische Prüfung von SBOM-basierten Schwachstellenbefunden und die Reproduzierbarkeit der zugrunde liegenden Evidenz unterstützen.",
			summaryAssemblyMath:               "Die Assembly behielt nach Normalisierung und Deduplikation %d Paketkomponenten und fügte %d strukturelle Container-Komponenten hinzu. Dadurch entstehen insgesamt %d CycloneDX-Komponenten.",
			summaryNextStepTemplate:           "Ein sinnvoller Einstieg ist %s, anschließend die zugehörige Objekt-ID im %s.",
			howToUseLead:                      "Der folgende Ablauf zeigt exemplarisch, wie Ergebnisse eines externen Vulnerability-Scans mit dem SBOM und diesem Bericht korreliert werden können. Das JSON-Beispiel verwendet Grype, weil dort die SBOM-Objekt-ID erhalten bleibt; bei anderen Werkzeugen sind die sinngemäß entsprechenden Felder zu verwenden.",
			howToUseStep1:                     "Wenn eine Grype-JSON-Ausgabe vorliegt, extrahieren Sie die für die Triage relevanten Felder und filtern Sie zunächst auf hohe und kritische Befunde. Beispiel:",
			howToUseStep2Template:             "Öffnen Sie den %s und suchen Sie nach dem Wert aus `artifact_id`. Die Überschrift `### <artifact_id>` entspricht der `bom-ref` im SBOM und der `artifact.id` in Grype.",
			howToUseStep3:                     "Verwenden Sie `Delivery path`, um die Fundstelle in der Lieferdatei nachzuvollziehen. Verwenden Sie `Evidence path` oder den Evidenzhinweistext, um die konkrete Grundlage der Paketidentifikation zu benennen.",
			howToUseStep4Template:             "Wenn unter einer Objekt-ID mehrere Delivery Paths aufgeführt sind, beschreibt der Bericht mehrere physische Vorkommen derselben Paketidentität, die bewusst zu einer Komponente zusammengeführt wurden. Die Zusammenführungslogik ist in %s erläutert. Fragen zu Abdeckungsgrenzen lassen sich über %s und %s einordnen.",
			methodLead:                        "Hier steht nur die Kurzfassung. Die vollständige operator-orientierte Erläuterung steht in SCAN_APPROACH.md auf GitHub.",
			methodBulletTwoPhases:             "Die Lieferung wird zunächst entpackt und in konkrete Artefakte gegliedert. Anschließend werden Paketmetadaten aus extrahierten Verzeichnisbäumen und aus direkt lesbaren Paketdateien gesammelt.",
			methodBulletEvidence:              "Paketidentitäten werden nur dann behauptet, wenn dafür beobachtbare Evidenz vorliegt, etwa Paketmanifeste, JAR-Metadaten, MSI-Property-Tabellen oder Binär-Metadaten.",
			methodBulletDedup:                 "Deduplikation ist nachvollziehbar: schwache Platzhalter und wiederholte PURLs werden entfernt, aber die überlebende Komponente behält die konkreten Blatt-Delivery- und Evidence-Pfade.",
			methodBulletTrust:                 "Der Lauf ist deterministisch: Die Eingabedatei ist gehasht, die Lieferpfade sind stabil und Fehler oder Abdeckungsgrenzen werden explizit protokolliert statt verborgen.",
			methodMoreDetails:                 "Vertiefung in SCAN_APPROACH.md:",
			appendixLead:                      "Die folgenden Abschnitte enthalten die vollständige Rohspur für Stichproben, vertiefte technische Prüfung und Belegexport. Sie sind bewusst ausführlich und werden typischerweise erst benötigt, wenn die relevante Objekt-ID oder der relevante Lieferpfad bereits feststeht.",
			summaryExtraction:                 "Extraktion",
			summaryScan:                       "Scans",
			summaryComponents:                 "Komponentenindex",
			summaryPolicies:                   "Richtlinienentscheidungen",
			summaryProcessingIssues:           "Verarbeitungsfehler",
			summaryFindings:                   "Wesentliche Befunde",
			endOfReport:                       "Ende des Berichts.",
			policyDecisionAt:                  "bei",
			linkTwoPhases:                     "Zwei Phasen",
			linkScanDetail:                    "Scan-Details",
			linkFinalSBOMBuild:                "Finaler SBOM-Aufbau",
			linkDeduplication:                 "Deduplikation",
			linkPackageDetectionReliability:   "Zuverlaessigkeit der Paketerkennung",
			summaryExtractionStatsTemplate:    "gesamt=%d extrahiert=%d syft-nativ=%d fehlgeschlagen=%d werkzeug-fehlt=%d uebersprungen=%d endungsgefiltert=%d ([Details](#%s)) sicherheitsblockiert=%d ausstehend=%d",
			summaryScanStatsTemplate:          "gesamt=%d erfolgreich=%d fehler=%d komponenten=%d",
			summaryComponentsStatsTemplate:    "%d roh -> entfernt %d (fs-artefakte=%d, low-value=%d, schwache-duplikate=%d, purl-duplikate=%d) -> %d im BOM -> gefiltert %d (abs-pfad=%d, low-value=%d, zusammengefuehrt=%d) -> indexiert %d",
			summaryPoliciesStatsTemplate:      "gesamt=%d weiter=%d ueberspringen=%d abbrechen=%d",
			summaryProcessingStatsTemplate:    "pipeline=%d",
			findingToolMissingTemplate:        "%d Extraktionsknoten benoetigen nicht verfuegbare externe Werkzeuge. Beispiele: %s.",
			findingExtractionGapTemplate:      "%d Extraktionsknoten sind fehlgeschlagen oder blockiert. Beispiele: %s.",
			findingScanFailedTemplate:         "%d Syft-Scan-Aufgaben sind fehlgeschlagen. Beispiele: %s.",
			findingAllScansSuccessfulTemplate: "Alle %d Syft-Scan-Aufgaben wurden erfolgreich abgeschlossen.",
			findingPURLCoverageTemplate:       "%d von %d indexierten Komponenten-Vorkommen [tragen eine PURL](#%s); [%d nicht](#%s).",
			findingNoPackageIdentityTemplate:  "%d erfolgreiche Scan-Aufgaben lieferten keine Paketidentitaet. Beispiele: %s.",
			findingIndexQualityTemplate:       "Die Index-Qualitaetsregeln entfernten %d absolute Pfad-Artefakte, %d Low-Value-Datei-Artefakte und fuehrten %d Platzhalter-Duplikate zusammen.",
			findingNoCriticalLimitations:      "Keine kritischen Verarbeitungsgrenzen in diesem Lauf erkannt.",
			processingPipelineLabel:           "pipeline",
			processingExtractionFailedLabel:   "extraktion-fehlgeschlagen",
			processingSecurityBlockedLabel:    "extraktion-sicherheitsblockiert",
			processingToolMissingLabel:        "extraktion-werkzeug-fehlt",
			processingScanErrorsLabel:         "scan-fehler",
			processingSourceHeader:            "Quelle",
			processingLocationHeader:          "Ort",
			processingDetailHeader:            "Detail",
			additionalEntriesOmittedTemplate:  "%d zusaetzliche Eintraege ausgelassen",
			noneValue:                         "keine",
			reasonLabel:                       "Grund",
			countLabel:                        "Anzahl",
			suppressionOperationalFS:          "Operative Bedeutung: Dies sind dateibasierte Syft-Eintraege und keine beibehaltenen Paketbefunde. Fuer Vulnerability-Triage ist hier normalerweise keine Aktion noetig. Sie werden nur fuer auditierbare Normalisierung dokumentiert.",
			suppressionOperationalFSFollowUp:  "Wenn fuer dieselbe Datei eine Paketidentitaet existiert, ist der relevante Eintrag die ueberlebende Komponente im Komponentenindex.",
			suppressionOperationalLowValue:    "Operative Bedeutung: Diese Roh-Dateieintraege hatten keine PURL, keine Version und keine identifizierenden Cataloger-Metadaten. Sie eignen sich nicht fuer paketbasierte CVE-Korrelation und werden daher aus der SBOM-Paketsicht ausgeschlossen.",
			suppressionOperationalWeakDup:     "Operative Bedeutung: Am selben Liefer-/Evidenz-Ort existierte bereits ein staerkerer Paketeintrag. Der schwaechere Platzhalter wurde entfernt, damit die finale SBOM die besser zurechenbare Identitaet behaelt.",
			suppressionOperationalPURLDup:     "Operative Bedeutung: Mehrere Rohbeobachtungen beschrieben dieselbe Paketidentitaet. Eine Repraesentation blieb erhalten; die ueberlebende Komponente im Komponentenindex traegt die beibehaltenen blattnahen Liefer- und Evidenzpfade. Diese Tabelle dient nur der Audit-Nachvollziehbarkeit der Zusammenfuehrung.",
			suppressionTableDeliveryPath:      "Lieferpfad",
			suppressionTableComponentName:     "Unterdrueckter Komponentenname",
			suppressionTableSuppressedBy:      "Unterdrueckt durch",
			extractionSandboxLabel:            "sandbox",

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
			suppressedByNoIndexedMatch:          "durch Normalisierungsregel entfernt; für diesen Lieferpfad existiert keine überlebende Paketkomponente (siehe [Komponentenindex](#component-occurrence-index))",
			suppressedByAmbiguousIndexedMatch:   "durch Normalisierungsregel entfernt; mehrere überlebende Paketkomponenten passen zu diesem Lieferpfad, daher erfolgt keine unsichere 1:1-Zuordnung (siehe [Komponentenindex](#component-occurrence-index))",
			suppressedByReplacementNotIndexed:   "durch Normalisierungsregel ersetzt; Ziel ist ein nicht indizierter Struktur-/Container-Eintrag (siehe [Extraktionsprotokoll](#extraction-log))",
		}
	default:
		return translations{
			title:                             "extract-sbom Audit Report",
			inputSection:                      "Input File",
			configSection:                     "Configuration",
			rootMetadataSection:               "Root SBOM Metadata",
			sandboxSection:                    "Sandbox Configuration",
			extractionSection:                 "Extraction Log",
			scanSection:                       "Scan Task Log",
			policySection:                     "Policy Decisions",
			summarySection:                    "Summary",
			residualRiskSection:               "Residual Risk and Limitations",
			processingIssuesSection:           "Processing Errors",
			field:                             "Field",
			value:                             "Value",
			source:                            "Source",
			setting:                           "Setting",
			filename:                          "Filename",
			filesize:                          "File size",
			unitBytes:                         "bytes",
			skipExtensions:                    "skip-extensions",
			nameLabel:                         "Name",
			manufacturerLabel:                 "Manufacturer",
			deliveryDateLabel:                 "Delivery Date",
			policyMode:                        "Policy mode",
			interpretMode:                     "Interpretation mode",
			language:                          "Language",
			maxDepth:                          "Max depth",
			maxFiles:                          "Max files",
			maxTotalSize:                      "Max total size",
			maxEntrySize:                      "Max entry size",
			maxRatio:                          "Max ratio",
			timeout:                           "Timeout",
			progressLevel:                     "Progress",
			generator:                         "extract-sbom build",
			sandboxName:                       "Sandbox",
			sandboxAvail:                      "Available",
			unsafeWarning:                     "WARNING",
			unsafeActive:                      "Unsafe mode active — no sandbox isolation",
			tableOfContentsSection:            "Table of Contents",
			howToUseSection:                   "How To Use This Report",
			methodOverviewSection:             "Method At A Glance",
			appendixSection:                   "Appendix",
			componentIndexSection:             "Component Occurrence Index",
			componentIndexLead:                "Entries are sorted by delivery path. The object ID matches the SBOM bom-ref and Grype artifact.id. `Delivery path` shows where the component occurs in the supplier delivery. `Evidence path` shows the concrete file or metadata source that supported the identification. If several delivery paths appear under one object ID, identical PURLs were intentionally merged and every concrete leaf-most occurrence path was retained.",
			noIndexedComponents:               "No component occurrences indexed.",
			objectID:                          "Object ID",
			packageName:                       "Package",
			version:                           "Version",
			purl:                              "PURL",
			evidencePath:                      "Evidence path",
			foundBy:                           "Found by",
			noEvidenceRecorded:                "no component-specific evidence recorded",
			processingTime:                    "Processing time",
			scanError:                         "Error:",
			componentsFound:                   "components found",
			noComponents:                      "no components found",
			scanSectionLead:                   "This is a per-scan-task execution log. Evidence lines in this section are task-level observations and may cover several final components. The authoritative per-component evidence statements are in the Component Occurrence Index.",
			scanTaskEvidenceLabel:             "evidence-path",
			scanNoPackageIDsSection:           "Scan Tasks Without Package Identities",
			scanNoPackageIDsLead:              "%d successful scan tasks produced no package identities. The complete list for audit traceability is shown below:",
			noScanNoPackageIDs:                "No scan tasks without package identities were observed in this run.",
			deliveryPath:                      "Delivery path",
			status:                            "Status",
			tool:                              "Tool",
			duration:                          "Duration",
			suppliedBy:                        "User-supplied",
			derived:                           "Auto-derived",
			residualRiskText:                  "The following points describe coverage boundaries and interpretation risks that matter when the SBOM is used for vulnerability assessment:",
			residualRiskProfileLead:           "The method is manifest- and metadata-based. Reliability is highest for formats with explicit package metadata, such as RPM, DEB, or Java archives with Maven or manifest metadata. Coverage is weaker for plain files, bundled copies without manifests, and Windows binaries with sparse or missing VERSIONINFO.",
			residualRiskAbsenceHint:           "The absence of a component from the SBOM is not proof that the underlying code is absent; it means only that no usable package-metadata evidence was observed for it.",
			residualRiskPURLCoverage:          "%d of %d indexed component occurrences carry a PURL. %d indexed occurrences do not carry a PURL and therefore usually correlate poorly or not at all with vulnerability databases.",
			residualRiskEvidenceCoverage:      "%d indexed occurrences carry a concrete evidence path. %d rely only on a generic evidence-source statement, and %d have no additional evidence detail beyond the component record.",
			residualRiskNoComponentTasks:      "%d of %d successful scan tasks produced no package identities. This means the content was seen, but no usable package metadata was present. Example tasks: %s.",
			residualRiskFileArtifactCoverage:  "Syft also emitted %d file-level records without actionable package coordinates. These records show that files were observed, but they do not by themselves support CVE matching and are therefore not listed as package findings.",
			residualRiskExtensionFilter:       "The extension filter excluded %d files from examination; these files are not reflected in the component inventory. Details: %s.",
			residualRiskExtractionGap:         "%d extraction nodes could not be processed completely. Examples: %s.",
			residualRiskToolGap:               "%d extraction nodes require unavailable helper tools. Examples: %s.",
			residualRiskScanGap:               "%d scan tasks failed. Examples: %s.",
			residualRiskMoreDetails:           "Background on package-detection reliability: %s.",
			noPolicyDecisions:                 "No policy decisions recorded.",
			noProcessingIssues:                "No processing issues recorded.",
			summaryLead:                       "This report documents the observed package findings, their traceability, and the processing limits of a single inspection run over the supplied delivery. Its purpose is to support technical review of SBOM-based vulnerability findings and reproducibility of the underlying evidence.",
			summaryAssemblyMath:               "Assembly retained %d package components after normalization and deduplication and added %d structural container components, resulting in %d CycloneDX components overall.",
			summaryNextStepTemplate:           "A practical starting point is %s, followed by the corresponding object in the %s.",
			howToUseLead:                      "The workflow below illustrates how results from an external vulnerability scan can be correlated with the SBOM and this report. The JSON example uses Grype because it preserves the SBOM object identifier; analogous fields can be taken from other tools.",
			howToUseStep1:                     "If Grype JSON output is available, extract the fields needed for triage and restrict the view to high and critical findings. Example:",
			howToUseStep2Template:             "Open the %s and search for the value from `artifact_id`. The heading `### <artifact_id>` corresponds to the SBOM `bom-ref` and to Grype `artifact.id`.",
			howToUseStep3:                     "Use `Delivery path` to locate the finding in the supplier delivery. Use `Evidence path` or the evidence-source text to identify the concrete manifest, metadata file, or cataloger basis behind the package identification.",
			howToUseStep4Template:             "If one object lists several delivery paths, the report is describing several physical occurrences that were consolidated into one package component because they share the same package identity. The consolidation logic is summarized in %s. Questions about coverage boundaries can be assessed with %s and %s.",
			methodLead:                        "This section is the compressed version. The full operator-oriented explanation lives in SCAN_APPROACH.md on GitHub.",
			methodBulletTwoPhases:             "The delivery is first unpacked and classified into concrete artifacts. Package metadata is then collected from extracted directory trees and from directly readable package files.",
			methodBulletEvidence:              "A package identity is asserted only when observable evidence exists, such as package manifests, JAR metadata, MSI property tables, or binary metadata.",
			methodBulletDedup:                 "Deduplication is traceable: weak placeholders and repeated PURLs are removed, but the surviving component keeps the concrete leaf-most delivery and evidence paths.",
			methodBulletTrust:                 "The run is deterministic: the input file is hash-pinned, logical delivery paths are stable, and errors or coverage limits are recorded instead of hidden.",
			methodMoreDetails:                 "Deep links into SCAN_APPROACH.md:",
			appendixLead:                      "The sections below preserve the detailed audit trail for spot checks, deeper technical review, and evidence export. They are intentionally exhaustive and are usually only needed once the relevant object id or delivery path is already known.",
			summaryExtraction:                 "Extraction",
			summaryScan:                       "Scans",
			summaryComponents:                 "Component index",
			summaryPolicies:                   "Policy decisions",
			summaryProcessingIssues:           "Processing issues",
			summaryFindings:                   "Key findings",
			endOfReport:                       "End of report.",
			policyDecisionAt:                  "at",
			linkTwoPhases:                     "Two phases",
			linkScanDetail:                    "Scan detail",
			linkFinalSBOMBuild:                "Final SBOM build",
			linkDeduplication:                 "Deduplication",
			linkPackageDetectionReliability:   "Package Detection Reliability",
			summaryExtractionStatsTemplate:    "total=%d extracted=%d syft-native=%d failed=%d tool-missing=%d skipped=%d extension-filtered=%d ([details](#%s)) security-blocked=%d pending=%d",
			summaryScanStatsTemplate:          "total=%d successful=%d errors=%d components-found=%d",
			summaryComponentsStatsTemplate:    "%d raw -> removed %d (fs-artifacts=%d, low-value=%d, weak-duplicates=%d, purl-duplicates=%d) -> %d in BOM -> filtered %d (abs-path=%d, low-value=%d, merged=%d) -> indexed %d",
			summaryPoliciesStatsTemplate:      "total=%d continue=%d skip=%d abort=%d",
			summaryProcessingStatsTemplate:    "pipeline=%d",
			findingToolMissingTemplate:        "%d extraction nodes require unavailable external tools. Examples: %s.",
			findingExtractionGapTemplate:      "%d extraction nodes failed or were blocked. Examples: %s.",
			findingScanFailedTemplate:         "%d Syft scan tasks failed. Examples: %s.",
			findingAllScansSuccessfulTemplate: "All %d Syft scan tasks completed successfully.",
			findingPURLCoverageTemplate:       "%d of %d indexed component occurrences [carry a PURL](#%s); [%d do not](#%s).",
			findingNoPackageIdentityTemplate:  "%d successful scan tasks produced no package identities. Examples: %s.",
			findingIndexQualityTemplate:       "Index quality controls removed %d absolute-path artifacts, %d low-value file artifacts, and merged %d duplicate placeholders.",
			findingNoCriticalLimitations:      "No critical processing limitations detected in this run.",
			processingPipelineLabel:           "pipeline",
			processingExtractionFailedLabel:   "extraction-failed",
			processingSecurityBlockedLabel:    "extraction-security-blocked",
			processingToolMissingLabel:        "extraction-tool-missing",
			processingScanErrorsLabel:         "scan-errors",
			processingSourceHeader:            "Source",
			processingLocationHeader:          "Location",
			processingDetailHeader:            "Detail",
			additionalEntriesOmittedTemplate:  "%d additional entries omitted",
			noneValue:                         "none",
			reasonLabel:                       "Reason",
			countLabel:                        "Count",
			suppressionOperationalFS:          "Operational meaning: these are file-level Syft records, not retained package findings. They normally require no action during vulnerability triage. They are listed here only so the normalization step remains auditable.",
			suppressionOperationalFSFollowUp:  "When a package identity exists for the same file, the actionable record is the surviving component in the Component Occurrence Index.",
			suppressionOperationalLowValue:    "Operational meaning: these raw file records had no PURL, no version, and no identifying cataloger metadata. They do not support package-level CVE correlation and are therefore excluded from the SBOM package view.",
			suppressionOperationalWeakDup:     "Operational meaning: at the same delivery/evidence locus a stronger package record existed. The weaker placeholder was removed so that the final SBOM keeps the more attributable identity.",
			suppressionOperationalPURLDup:     "Operational meaning: several raw observations described the same package identity. One representative was kept, and the surviving component in the Component Occurrence Index carries the retained leaf-most delivery and evidence paths. Use this table only when you need to audit why duplicate raw observations collapsed into one package component.",
			suppressionTableDeliveryPath:      "Delivery path",
			suppressionTableComponentName:     "Suppressed component name",
			suppressionTableSuppressedBy:      "Suppressed by",
			extractionSandboxLabel:            "sandbox",

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
			suppressedByNoIndexedMatch:          "removed by normalization rule; no surviving package component exists for this delivery path (see [Component Occurrence Index](#component-occurrence-index))",
			suppressedByAmbiguousIndexedMatch:   "removed by normalization rule; multiple surviving package components match this delivery path, so no unsafe 1:1 assignment is made (see [Component Occurrence Index](#component-occurrence-index))",
			suppressedByReplacementNotIndexed:   "replaced by normalization rule; target is a non-indexed structural/container entry (see [Extraction Log](#extraction-log))",
		}
	}
}
