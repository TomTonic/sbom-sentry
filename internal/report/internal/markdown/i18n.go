package markdown

// translations contains all localized report labels and prose snippets used
// by markdown-report generation.
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

// getTranslations returns the translation bundle for the requested language,
// defaulting to English when an unknown code is provided.
func getTranslations(lang string) translations {
	switch lang {
	case "de":
		return translationsDE()
	default:
		return translationsEN()
	}
}
