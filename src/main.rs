use std::path::Path;
use yara::*;

fn compile_yara_file(rule_file: &Path) -> Result<Rules, yara::Error>{
    let mut compiler = Compiler::new()?.add_rules_file(&rule_file)?;
    let compiled_rule_file = compiler.compile_rules()?;
    Ok(compiled_rule_file)
}

fn compile_yara_rule(rule: &str) -> Result<Rules, yara::Error> {
    let mut compiler = Compiler::new()?.add_rules_str(rule)?;
    let compiled_rule = compiler.compile_rules()?;
    Ok(compiled_rule)
}

fn scan_file(compiled_rules: Result<Rules, Error>, scan_file: &str) {
    match compiled_rules {
        Ok(compiled_rules) => {
            let mut scanner = compiled_rules.scanner().unwrap();
            let results = scanner.scan_file(scan_file).unwrap();

            if !results.is_empty() {
                for yara_match in results {
                    println!("Rule match: {}", yara_match.identifier)
                }

            } else {
                println!("No YARA Matches!")
            }
        }
        Err(err) => {
            eprintln!("Error compiling YARA rule: {}", err);
        }
    }
}

fn main() {
    // FILE TO SCAN
    let file_to_scan = "./test/test_exe";
    let file_that_fails_scan = "./test/test_arm";
    // YARA FILE
    let yara_file_str = "pe_file.yara";
    let yara_file_path = Path::new(yara_file_str);
    let compiled_file = compile_yara_file(&yara_file_path);
    scan_file(compiled_file, file_that_fails_scan);

    // YARA RULE
    let yara_rule = "rule is_pe{meta: description = \"Detects 'MZ header'\" author = \"Peter Girnus\" web = \"https://www.petergirnus.com/blog\" condition:		uint16(0) == 0x5a4d}";
    let compiled_rule = compile_yara_rule(yara_rule);
    scan_file(compiled_rule, file_to_scan);

}