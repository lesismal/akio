//! NIST PKITS (Public Key Interoperability Test Suite, 2011 data): every test of section 4 of
//! the PKITS document, with the policy settings it lists, run through `Verifier` with
//! revocation required (`RevocationMode::HardFail`, every CRL of the suite in the set).
//!
//! The suite is downloaded, not vendored: `tools/pkits/prepare.sh <dir>`, then
//! `PKITS_DIR=<dir> cargo test -p only-x509 --test pkits -- --ignored --nocapture`.
//! Tests this crate deliberately does not support are listed in `UNSUPPORTED` with the
//! reason; they must keep failing the expected way (a test that starts passing is reported
//! so the list stays honest).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use only_x509::{Certificate, CrlSet, PolicyOptions, RevocationMode, RootStore, Usage, Verifier};

/// One validation run: `(initial-explicit-policy, initial-policy-set (NIST-test-policy-N
/// numbers; empty = any-policy), initial-policy-mapping-inhibit, initial-inhibit-any-policy,
/// expected to validate)`.
type Run = (bool, &'static [u8], bool, bool, bool);

const fn r(explicit: bool, set: &'static [u8], map: bool, any: bool, ok: bool) -> Run {
    (explicit, set, map, any, ok)
}

/// `(section, test name as in the file names, runs)`, from the PKITS document.
const CASES: &[(&str, &str, &[Run])] = &[
    (
        "4.1.1",
        "ValidSignaturesTest1",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.1.2",
        "InvalidCASignatureTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.1.3",
        "InvalidEESignatureTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.1.4",
        "ValidDSASignaturesTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.1.5",
        "ValidDSAParameterInheritanceTest5",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.1.6",
        "InvalidDSASignatureTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.2.1",
        "InvalidCAnotBeforeDateTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.2.2",
        "InvalidEEnotBeforeDateTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.2.3",
        "Validpre2000UTCnotBeforeDateTest3",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.2.4",
        "ValidGeneralizedTimenotBeforeDateTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.2.5",
        "InvalidCAnotAfterDateTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.2.6",
        "InvalidEEnotAfterDateTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.2.7",
        "Invalidpre2000UTCEEnotAfterDateTest7",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.2.8",
        "ValidGeneralizedTimenotAfterDateTest8",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.1",
        "InvalidNameChainingEETest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.3.2",
        "InvalidNameChainingOrderTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.3.3",
        "ValidNameChainingWhitespaceTest3",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.4",
        "ValidNameChainingWhitespaceTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.5",
        "ValidNameChainingCapitalizationTest5",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.6",
        "ValidNameChainingUIDsTest6",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.7",
        "ValidRFC3280MandatoryAttributeTypesTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.8",
        "ValidRFC3280OptionalAttributeTypesTest8",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.9",
        "ValidUTF8StringEncodedNamesTest9",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.10",
        "ValidRolloverfromPrintableStringtoUTF8StringTest10",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.3.11",
        "ValidUTF8StringCaseInsensitiveMatchTest11",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.1",
        "MissingCRLTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.2",
        "InvalidRevokedCATest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.3",
        "InvalidRevokedEETest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.4",
        "InvalidBadCRLSignatureTest4",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.5",
        "InvalidBadCRLIssuerNameTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.6",
        "InvalidWrongCRLTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.7",
        "ValidTwoCRLsTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.8",
        "InvalidUnknownCRLEntryExtensionTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.9",
        "InvalidUnknownCRLExtensionTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.10",
        "InvalidUnknownCRLExtensionTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.11",
        "InvalidOldCRLnextUpdateTest11",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.12",
        "Invalidpre2000CRLnextUpdateTest12",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.13",
        "ValidGeneralizedTimeCRLnextUpdateTest13",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.14",
        "ValidNegativeSerialNumberTest14",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.15",
        "InvalidNegativeSerialNumberTest15",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.16",
        "ValidLongSerialNumberTest16",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.17",
        "ValidLongSerialNumberTest17",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.18",
        "InvalidLongSerialNumberTest18",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.19",
        "ValidSeparateCertificateandCRLKeysTest19",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.4.20",
        "InvalidSeparateCertificateandCRLKeysTest20",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.4.21",
        "InvalidSeparateCertificateandCRLKeysTest21",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.5.1",
        "ValidBasicSelfIssuedOldWithNewTest1",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.5.2",
        "InvalidBasicSelfIssuedOldWithNewTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.5.3",
        "ValidBasicSelfIssuedNewWithOldTest3",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.5.4",
        "ValidBasicSelfIssuedNewWithOldTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.5.5",
        "InvalidBasicSelfIssuedNewWithOldTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.5.6",
        "ValidBasicSelfIssuedCRLSigningKeyTest6",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.5.7",
        "InvalidBasicSelfIssuedCRLSigningKeyTest7",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.5.8",
        "InvalidBasicSelfIssuedCRLSigningKeyTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.1",
        "InvalidMissingbasicConstraintsTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.2",
        "InvalidcAFalseTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.3",
        "InvalidcAFalseTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.4",
        "ValidbasicConstraintsNotCriticalTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.6.5",
        "InvalidpathLenConstraintTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.6",
        "InvalidpathLenConstraintTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.7",
        "ValidpathLenConstraintTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.6.8",
        "ValidpathLenConstraintTest8",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.6.9",
        "InvalidpathLenConstraintTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.10",
        "InvalidpathLenConstraintTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.11",
        "InvalidpathLenConstraintTest11",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.12",
        "InvalidpathLenConstraintTest12",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.13",
        "ValidpathLenConstraintTest13",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.6.14",
        "ValidpathLenConstraintTest14",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.6.15",
        "ValidSelfIssuedpathLenConstraintTest15",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.6.16",
        "InvalidSelfIssuedpathLenConstraintTest16",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.6.17",
        "ValidSelfIssuedpathLenConstraintTest17",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.7.1",
        "InvalidkeyUsageCriticalkeyCertSignFalseTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.7.2",
        "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.7.3",
        "ValidkeyUsageNotCriticalTest3",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.7.4",
        "InvalidkeyUsageCriticalcRLSignFalseTest4",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.7.5",
        "InvalidkeyUsageNotCriticalcRLSignFalseTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.1",
        "AllCertificatesSamePolicyTest1",
        &[
            r(true, &[], false, false, true),
            r(true, &[1], false, false, true),
            r(true, &[2], false, false, false),
            r(true, &[1, 2], false, false, true),
        ],
    ),
    (
        "4.8.2",
        "AllCertificatesNoPoliciesTest2",
        &[
            r(false, &[], false, false, true),
            r(true, &[], false, false, false),
        ],
    ),
    (
        "4.8.3",
        "DifferentPoliciesTest3",
        &[
            r(false, &[], false, false, true),
            r(true, &[], false, false, false),
            r(true, &[1, 2], false, false, false),
        ],
    ),
    (
        "4.8.4",
        "DifferentPoliciesTest4",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.5",
        "DifferentPoliciesTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.6",
        "OverlappingPoliciesTest6",
        &[
            r(false, &[], false, false, true),
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, false),
        ],
    ),
    (
        "4.8.7",
        "DifferentPoliciesTest7",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.8",
        "DifferentPoliciesTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.9",
        "DifferentPoliciesTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.10",
        "AllCertificatesSamePoliciesTest10",
        &[
            r(false, &[], false, false, true),
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, true),
        ],
    ),
    (
        "4.8.11",
        "AllCertificatesAnyPolicyTest11",
        &[
            r(false, &[], false, false, true),
            r(false, &[1], false, false, true),
        ],
    ),
    (
        "4.8.12",
        "DifferentPoliciesTest12",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.8.13",
        "AllCertificatesSamePoliciesTest13",
        &[
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, true),
            r(false, &[3], false, false, true),
        ],
    ),
    (
        "4.8.14",
        "AnyPolicyTest14",
        &[
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, false),
        ],
    ),
    (
        "4.8.15",
        "UserNoticeQualifierTest15",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.8.16",
        "UserNoticeQualifierTest16",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.8.17",
        "UserNoticeQualifierTest17",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.8.18",
        "UserNoticeQualifierTest18",
        &[
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, true),
        ],
    ),
    (
        "4.8.19",
        "UserNoticeQualifierTest19",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.8.20",
        "CPSPointerQualifierTest20",
        &[
            r(false, &[], false, false, true),
            r(true, &[], false, false, true),
        ],
    ),
    (
        "4.9.1",
        "ValidRequireExplicitPolicyTest1",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.9.2",
        "ValidRequireExplicitPolicyTest2",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.9.3",
        "InvalidRequireExplicitPolicyTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.9.4",
        "ValidRequireExplicitPolicyTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.9.5",
        "InvalidRequireExplicitPolicyTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.9.6",
        "ValidSelfIssuedrequireExplicitPolicyTest6",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.9.7",
        "InvalidSelfIssuedrequireExplicitPolicyTest7",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.9.8",
        "InvalidSelfIssuedrequireExplicitPolicyTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.10.1",
        "ValidPolicyMappingTest1",
        &[
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, false),
            r(false, &[], true, false, false),
        ],
    ),
    (
        "4.10.2",
        "InvalidPolicyMappingTest2",
        &[
            r(false, &[], false, false, false),
            r(false, &[], true, false, false),
        ],
    ),
    (
        "4.10.3",
        "ValidPolicyMappingTest3",
        &[
            r(false, &[1], false, false, false),
            r(false, &[2], false, false, true),
        ],
    ),
    (
        "4.10.4",
        "InvalidPolicyMappingTest4",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.10.5",
        "ValidPolicyMappingTest5",
        &[
            r(false, &[1], false, false, true),
            r(false, &[6], false, false, false),
        ],
    ),
    (
        "4.10.6",
        "ValidPolicyMappingTest6",
        &[
            r(false, &[1], false, false, true),
            r(false, &[6], false, false, false),
        ],
    ),
    (
        "4.10.7",
        "InvalidMappingFromanyPolicyTest7",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.10.8",
        "InvalidMappingToanyPolicyTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.10.9",
        "ValidPolicyMappingTest9",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.10.10",
        "InvalidPolicyMappingTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.10.11",
        "ValidPolicyMappingTest11",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.10.12",
        "ValidPolicyMappingTest12",
        &[
            r(false, &[1], false, false, true),
            r(false, &[2], false, false, true),
        ],
    ),
    (
        "4.10.13",
        "ValidPolicyMappingTest13",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.10.14",
        "ValidPolicyMappingTest14",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.11.1",
        "InvalidinhibitPolicyMappingTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.2",
        "ValidinhibitPolicyMappingTest2",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.11.3",
        "InvalidinhibitPolicyMappingTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.4",
        "ValidinhibitPolicyMappingTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.11.5",
        "InvalidinhibitPolicyMappingTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.6",
        "InvalidinhibitPolicyMappingTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.7",
        "ValidSelfIssuedinhibitPolicyMappingTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.11.8",
        "InvalidSelfIssuedinhibitPolicyMappingTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.9",
        "InvalidSelfIssuedinhibitPolicyMappingTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.10",
        "InvalidSelfIssuedinhibitPolicyMappingTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.11.11",
        "InvalidSelfIssuedinhibitPolicyMappingTest11",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.12.1",
        "InvalidinhibitAnyPolicyTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.12.2",
        "ValidinhibitAnyPolicyTest2",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.12.3",
        "inhibitAnyPolicyTest3",
        &[
            r(false, &[], false, false, true),
            r(false, &[], false, true, false),
        ],
    ),
    (
        "4.12.4",
        "InvalidinhibitAnyPolicyTest4",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.12.5",
        "InvalidinhibitAnyPolicyTest5",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.12.6",
        "InvalidinhibitAnyPolicyTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.12.7",
        "ValidSelfIssuedinhibitAnyPolicyTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.12.8",
        "InvalidSelfIssuedinhibitAnyPolicyTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.12.9",
        "ValidSelfIssuedinhibitAnyPolicyTest9",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.12.10",
        "InvalidSelfIssuedinhibitAnyPolicyTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.1",
        "ValidDNnameConstraintsTest1",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.2",
        "InvalidDNnameConstraintsTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.3",
        "InvalidDNnameConstraintsTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.4",
        "ValidDNnameConstraintsTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.5",
        "ValidDNnameConstraintsTest5",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.6",
        "ValidDNnameConstraintsTest6",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.7",
        "InvalidDNnameConstraintsTest7",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.8",
        "InvalidDNnameConstraintsTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.9",
        "InvalidDNnameConstraintsTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.10",
        "InvalidDNnameConstraintsTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.11",
        "ValidDNnameConstraintsTest11",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.12",
        "InvalidDNnameConstraintsTest12",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.13",
        "InvalidDNnameConstraintsTest13",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.14",
        "ValidDNnameConstraintsTest14",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.15",
        "InvalidDNnameConstraintsTest15",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.16",
        "InvalidDNnameConstraintsTest16",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.17",
        "InvalidDNnameConstraintsTest17",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.18",
        "ValidDNnameConstraintsTest18",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.19",
        "ValidSelfIssuedDNnameConstraintsTest19",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.20",
        "InvalidSelfIssuedDNnameConstraintsTest20",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.21",
        "ValidRFC822nameConstraintsTest21",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.22",
        "InvalidRFC822nameConstraintsTest22",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.23",
        "ValidRFC822nameConstraintsTest23",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.24",
        "InvalidRFC822nameConstraintsTest24",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.25",
        "ValidRFC822nameConstraintsTest25",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.26",
        "InvalidRFC822nameConstraintsTest26",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.27",
        "ValidDNandRFC822nameConstraintsTest27",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.28",
        "InvalidDNandRFC822nameConstraintsTest28",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.29",
        "InvalidDNandRFC822nameConstraintsTest29",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.30",
        "ValidDNSnameConstraintsTest30",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.31",
        "InvalidDNSnameConstraintsTest31",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.32",
        "ValidDNSnameConstraintsTest32",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.33",
        "InvalidDNSnameConstraintsTest33",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.34",
        "ValidURInameConstraintsTest34",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.35",
        "InvalidURInameConstraintsTest35",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.36",
        "ValidURInameConstraintsTest36",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.13.37",
        "InvalidURInameConstraintsTest37",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.13.38",
        "InvalidDNSnameConstraintsTest38",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.1",
        "ValiddistributionPointTest1",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.2",
        "InvaliddistributionPointTest2",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.3",
        "InvaliddistributionPointTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.4",
        "ValiddistributionPointTest4",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.5",
        "ValiddistributionPointTest5",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.6",
        "InvaliddistributionPointTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.7",
        "ValiddistributionPointTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.8",
        "InvaliddistributionPointTest8",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.9",
        "InvaliddistributionPointTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.10",
        "ValidNoissuingDistributionPointTest10",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.11",
        "InvalidonlyContainsUserCertsCRLTest11",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.12",
        "InvalidonlyContainsCACertsCRLTest12",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.13",
        "ValidonlyContainsCACertsCRLTest13",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.14",
        "InvalidonlyContainsAttributeCertsTest14",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.15",
        "InvalidonlySomeReasonsTest15",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.16",
        "InvalidonlySomeReasonsTest16",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.17",
        "InvalidonlySomeReasonsTest17",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.18",
        "ValidonlySomeReasonsTest18",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.19",
        "ValidonlySomeReasonsTest19",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.20",
        "InvalidonlySomeReasonsTest20",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.21",
        "InvalidonlySomeReasonsTest21",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.22",
        "ValidIDPwithindirectCRLTest22",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.23",
        "InvalidIDPwithindirectCRLTest23",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.24",
        "ValidIDPwithindirectCRLTest24",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.25",
        "ValidIDPwithindirectCRLTest25",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.26",
        "InvalidIDPwithindirectCRLTest26",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.27",
        "InvalidcRLIssuerTest27",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.28",
        "ValidcRLIssuerTest28",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.29",
        "ValidcRLIssuerTest29",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.30",
        "ValidcRLIssuerTest30",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.31",
        "InvalidcRLIssuerTest31",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.32",
        "InvalidcRLIssuerTest32",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.33",
        "ValidcRLIssuerTest33",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.14.34",
        "InvalidcRLIssuerTest34",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.14.35",
        "InvalidcRLIssuerTest35",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.15.1",
        "InvaliddeltaCRLIndicatorNoBaseTest1",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.15.2",
        "ValiddeltaCRLTest2",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.15.3",
        "InvaliddeltaCRLTest3",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.15.4",
        "InvaliddeltaCRLTest4",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.15.5",
        "ValiddeltaCRLTest5",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.15.6",
        "InvaliddeltaCRLTest6",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.15.7",
        "ValiddeltaCRLTest7",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.15.8",
        "ValiddeltaCRLTest8",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.15.9",
        "InvaliddeltaCRLTest9",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.15.10",
        "InvaliddeltaCRLTest10",
        &[r(false, &[], false, false, false)],
    ),
    (
        "4.16.1",
        "ValidUnknownNotCriticalCertificateExtensionTest1",
        &[r(false, &[], false, false, true)],
    ),
    (
        "4.16.2",
        "InvalidUnknownCriticalCertificateExtensionTest2",
        &[r(false, &[], false, false, false)],
    ),
];

/// Tests that fail on purpose, with the reason.
const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "4.1.5",
        "DSA parameter inheritance (a DSA key without parameters takes its issuer's, RFC 3279 \
         §2.3.2): not supported, such a key does not parse",
    ),
    (
        "4.3.3",
        "names are chained by their DER bytes (RFC 5280 §7.1 allows it; as rustls-webpki), \
         not with the case and whitespace folding of RFC 4518",
    ),
    ("4.3.4", "as 4.3.3: whitespace folding"),
    ("4.3.5", "as 4.3.3: case folding"),
    (
        "4.3.10",
        "as 4.3.3: PrintableString and UTF8String compared as different",
    ),
    ("4.3.11", "as 4.3.3: case folding of UTF8String"),
];

/// NIST-test-policy-N: 2.16.840.1.101.3.2.1.48.N.
fn nist_policy(n: u8) -> Vec<u8> {
    vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, n]
}

fn find_ci(dir: &Path, name: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.eq_ignore_ascii_case(name))
        })
}

#[test]
#[ignore = "needs the PKITS data: PKITS_DIR=<dir> after tools/pkits/prepare.sh <dir>"]
fn pkits() {
    let Some(dir) = std::env::var_os("PKITS_DIR").map(PathBuf::from) else {
        eprintln!("PKITS_DIR not set; skipping");
        return;
    };
    let read = |p: &Path| std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let root =
        Certificate::from_der(read(&dir.join("certs/TrustAnchorRootCertificate.crt"))).unwrap();
    let mut roots = RootStore::new();
    roots.add(root);
    let mut crls = CrlSet::new();
    let mut bad_crls = 0;
    for e in std::fs::read_dir(dir.join("crls")).unwrap().flatten() {
        if let Err(err) = crls.add_der(read(&e.path())) {
            eprintln!("CRL {} does not parse: {err}", e.path().display());
            bad_crls += 1;
        }
    }
    // Inside the validity of the suite's certificates and CRLs (2010–2030).
    let now = 1_700_000_000;
    let (mut pass, mut fail) = (0, Vec::new());
    let mut unsupported_ok = Vec::new();
    for &(id, name, runs) in CASES {
        // The signed message carries the path; its signer, the end entity, has "EE" in its
        // common name.
        let bundle = std::fs::read(dir.join(format!("paths/{name}.pem"))).unwrap_or_default();
        let mut certs = Vec::new();
        let mut last_parsed = true;
        for der in only_crypto::pem::decode_label(&bundle, "CERTIFICATE").unwrap_or_default() {
            match Certificate::from_der(der) {
                Ok(c) => {
                    certs.push(c);
                    last_parsed = true;
                }
                Err(e) => {
                    eprintln!("{id} {name}: a certificate of the path does not parse: {e}");
                    last_parsed = false;
                }
            }
        }
        let is_ee = |c: &Certificate| {
            c.subject()
                .common_name()
                .is_some_and(|cn| cn.split(' ').any(|w| w == "EE"))
        };
        // Else the last one (a self-issued end entity in 4.13.20), if it parsed.
        let last = certs.last().filter(|_| last_parsed);
        let leaf = match certs.iter().rev().find(|c| is_ee(c)).or(last) {
            Some(c) => Some(c.clone()),
            None => {
                // The EE file itself (when the message has no parsable path).
                let p = find_ci(&dir.join("certs"), &format!("{name}EE.crt"));
                p.and_then(|p| Certificate::from_der(read(&p)).ok())
            }
        };
        if leaf.is_none() {
            eprintln!("{id} {name}: no end-entity certificate");
        }
        let others: Vec<Certificate> = certs
            .into_iter()
            .filter(|c| leaf.as_ref() != Some(c))
            .collect();
        for (k, &(explicit, set, map, any, ok)) in runs.iter().enumerate() {
            let mut opts = PolicyOptions::new();
            opts.explicit_policy = explicit;
            opts.initial_policy_set = set.iter().map(|&n| nist_policy(n)).collect();
            opts.inhibit_policy_mapping = map;
            opts.inhibit_any_policy = any;
            let got = match &leaf {
                Some(leaf) => Verifier::new(&roots)
                    .at_time(now)
                    .usage(Usage::Any)
                    .allow_ca_end_entity(true)
                    .crls(&crls)
                    .revocation_mode(RevocationMode::HardFail)
                    .policies(opts)
                    .verify_path(leaf, &others, None)
                    .map(|p| p.policies),
                None => Err(only_x509::Error::Encoding),
            };
            let tag = format!("{id} {name} #{}", k + 1);
            let unsupported = UNSUPPORTED.iter().any(|(u, _)| *u == id);
            if got.is_ok() == ok {
                if unsupported {
                    unsupported_ok.push(tag);
                } else {
                    pass += 1;
                }
            } else if !unsupported {
                fail.push(format!(
                    "{tag}: expected {}, got {got:?}",
                    if ok { "valid" } else { "invalid" }
                ));
            }
        }
    }
    let runs: usize = CASES.iter().map(|c| c.2.len()).sum();
    eprintln!(
        "PKITS: {pass}/{runs} runs as expected, {} unsupported, {} CRLs not parsed",
        UNSUPPORTED.len(),
        bad_crls
    );
    for f in &fail {
        eprintln!("FAIL {f}");
    }
    for u in &unsupported_ok {
        eprintln!("NOW PASSES (remove from UNSUPPORTED): {u}");
    }
    assert!(fail.is_empty() && unsupported_ok.is_empty());
}
