// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import Fuzzilli

let jsFileExtension = ".js"
let protoBufFileExtension = ".fzil"

let jsPrefix = ""
let jsSuffix = ""

let fuzzILLifter = FuzzILLifter()

// Create a specialized mock fuzzer that only uses specific generators
func makeMockFuzzerWithOnlySpecificGenerators(_ targetGenerators: [(CodeGenerator, Int)]) -> Fuzzer {
    // Create configuration  
    let config = Configuration(logLevel: .warning, enableInspection: true)
    let environment = JavaScriptEnvironment()

    return makeMockFuzzer(
        config: config,
        environment: environment,
        codeGenerators: targetGenerators,
        onlyUseSpecified: true
    )
}

// Loads a serialized FuzzIL program from the given file
func loadProgram(from path: String) throws -> Program {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let proto = try Fuzzilli_Protobuf_Program(serializedBytes: data)
    let program = try Program(from: proto)
    return program
}

func loadAllPrograms(in dirPath: String) -> [(filename: String, program: Program)] {
    var isDir: ObjCBool = false
    if !FileManager.default.fileExists(atPath: dirPath, isDirectory:&isDir) || !isDir.boolValue {
        print("\(dirPath) is not a directory!")
        exit(-1)
    }

    let fileEnumerator = FileManager.default.enumerator(atPath: dirPath)
    var results = [(String, Program)]()
    while let filename = fileEnumerator?.nextObject() as? String {
        guard filename.hasSuffix(protoBufFileExtension) else { continue }
        let path = dirPath + "/" + filename
        do {
            let program = try loadProgram(from: path)
            results.append((filename, program))
        } catch FuzzilliError.programDecodingError(let reason) {
            print("Failed to load program \(path): \(reason)")
        } catch {
            print("Failed to load program \(path) due to unexpected error: \(error)")
        }
    }
    return results
}

// Takes a program and lifts it to JavaScript.
func liftToJS(_ jsLifter: JavaScriptLifter,_ prog: Program) -> String {
    let res = jsLifter.lift(prog)
    return res.trimmingCharacters(in: .whitespacesAndNewlines)
}

// Takes a program and lifts it to FuzzIL's text format.
func liftToFuzzIL(_ prog: Program) -> String {
    let res = fuzzILLifter.lift(prog)
    return res.trimmingCharacters(in: .whitespacesAndNewlines)
}

// Loads all .fzil files in a directory, and lifts them to JS.
// Returns the number of files successfully converted.
func liftAllPrograms(in dirPath: String, with lifter: Lifter, fileExtension: String) -> Int {
    var numLiftedPrograms = 0
    for (filename, program) in loadAllPrograms(in: dirPath) {
        let newFilePath = "\(dirPath)/\(filename.dropLast(protoBufFileExtension.count))\(fileExtension)"
        let content = lifter.lift(program)
        do {
            try content.write(to: URL(fileURLWithPath: newFilePath), atomically: false, encoding: String.Encoding.utf8)
            numLiftedPrograms += 1
        } catch {
            print("Failed to write file \(newFilePath): \(error)")
        }
    }
    return numLiftedPrograms
}

func loadProgramOrExit(from path: String) -> Program {
    do {
        return try loadProgram(from: path)
    } catch {
        print("Failed to load program from \(path): \(error)")
        exit(-1)
    }
}

let args = Arguments.parse(from: CommandLine.arguments)

if args["-h"] != nil || args["--help"] != nil || args.numPositionalArguments != 1 || args.numOptionalArguments > 2 {
    print("""
          Usage:
          \(args.programName) options path

          Options:
              --liftToFuzzIL           : Lifts the given protobuf program to FuzzIL's text format and prints it
              --liftToJS               : Lifts the given protobuf program to JS and prints it
              --liftCorpusToJS         : Loads all .fzil files in a directory and lifts them to .js files in that same directory
              --dumpProtobuf           : Dumps the raw content of the given protobuf file
              --dumpProgram            : Dumps the internal representation of the program stored in the given protobuf file
              --checkCorpus            : Attempts to load all .fzil files in a directory and checks if they are statically valid
              --compile                : Compile the given JavaScript program to a FuzzIL program. Requires node.js
              --generate               : Generate a random program using Fuzzilli's code generators and save it to the specified path.
              --test-generator <name>  : Test a specific code generator by name (e.g., ForOfLoopGenerator) and save the result.
              --test-template <name>   : Test a specific program template by name (e.g., AsyncFunctionFuzzer) and save the result.
              --forDifferentialFuzzing : Enable additional features for better support of external differential fuzzing.
          """)
    exit(0)
}

let path = args[0]

let forDifferentialFuzzing = args.has("--forDifferentialFuzzing")
let jsLifter = JavaScriptLifter(prefix: jsPrefix, suffix: jsSuffix, ecmaVersion: ECMAScriptVersion.es6, environment: JavaScriptEnvironment(), alwaysEmitVariables: forDifferentialFuzzing)

// Covert a single IL protobuf file to FuzzIL's text format and print to stdout
if args.has("--liftToFuzzIL") {
    let program = loadProgramOrExit(from: path)
    print(liftToFuzzIL(program))
}

// Covert a single IL protobuf file to JS and print to stdout
else if args.has("--liftToJS") {
    let program = loadProgramOrExit(from: path)
    print(liftToJS(jsLifter, program))
}

// Lift all protobuf programs to JavaScript
else if args.has("--liftCorpusToJS") {
    let numLiftedPrograms = liftAllPrograms(in: path, with: jsLifter, fileExtension: jsFileExtension)
    print("Lifted \(numLiftedPrograms) programs to JS")
}

// Pretty print just the protobuf, without trying to load as a program
// This allows the debugging of produced programs that are not syntactically valid
else if args.has("--dumpProtobuf") {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let proto = try Fuzzilli_Protobuf_Program(serializedBytes: data)
    dump(proto, maxDepth: 3)
}

// Pretty print a protobuf as a program on stdout
else if args.has("--dumpProgram") {
    let program = loadProgramOrExit(from: path)
    print("Now start dumping program")
    dump(program)
}

// Combine multiple protobuf programs into a single corpus file
else if args.has("--checkCorpus") {
    let numPrograms = loadAllPrograms(in: path).count
    print("Successfully loaded \(numPrograms) programs")
}

// Compile a JavaScript program to a FuzzIL program. Requires node.js
else if args.has("--compile") {
    // We require a NodeJS executor here as we need certain node modules.
    guard let nodejs = JavaScriptExecutor(type: .nodejs) else {
        print("Could not find the NodeJS executable.")
        exit(-1)
    }
    guard let parser = JavaScriptParser(executor: nodejs) else {
        print("The JavaScript parser does not appear to be working. See Sources/Fuzzilli/Compiler/Parser/README.md for instructions on how to set it up.")
        exit(-1)
    }

    let ast: JavaScriptParser.AST
    do {
        ast = try parser.parse(path)
    } catch {
        print("Failed to parse \(path): \(error)")
        exit(-1)
    }

    let compiler = JavaScriptCompiler()
    let program: Program
    do {
        program = try compiler.compile(ast)
    } catch {
        print("Failed to compile: \(error)")
        exit(-1)
    }

    print(fuzzILLifter.lift(program))
    print()
    print(jsLifter.lift(program))

    do {
        let outputPath = URL(fileURLWithPath: path).deletingPathExtension().appendingPathExtension("fzil")
        try program.asProtobuf().serializedData().write(to: outputPath)
        print("FuzzIL program written to \(outputPath.relativePath)")
    } catch {
        print("Failed to store output program to disk: \(error)")
        exit(-1)
    }
}

else if args.has("--generate") {
    let fuzzer = makeMockFuzzer(config: Configuration(logLevel: .warning, enableInspection: true), environment: JavaScriptEnvironment())
    let b = fuzzer.makeBuilder()
    b.buildPrefix()
    b.build(n: 50, by: .generating)
    let program = b.finalize()

    let js_program = jsLifter.lift(program, withOptions: .includeComments)
    // save js_program to a js file
    let js_program_path = URL(fileURLWithPath: path).deletingPathExtension().appendingPathExtension("js")
    try js_program.write(to: js_program_path, atomically: false, encoding: String.Encoding.utf8)

    print(jsLifter.lift(program, withOptions: .includeComments))

    do {
        let outputPath = URL(fileURLWithPath: path).deletingPathExtension().appendingPathExtension("fzil")
        try program.asProtobuf().serializedData().write(to: outputPath)
    } catch {
        print("Failed to store output program to disk: \(error)")
        exit(-1)
    }
}

else if args.has("--test-generator") {
    guard let generatorName = args["--test-generator"] else {
        print("Error: --test-generator requires a generator name")
        exit(-1)
    }
    
    // Find the specified generator
    guard let targetGenerator = CodeGenerators.first(where: { $0.name == generatorName }) else {
        print("Error: Generator '\(generatorName)' not found")
        print("Available generators:")
        for generator in CodeGenerators {
            print("  - \(generator.name)")
        }
        exit(-1)
    }
    
    print("Testing generator: \(targetGenerator.name)")
    
    // Create a mock fuzzer with only the specified generator plus essential bootstrapping ones
    var essentialGenerators = [
        (CodeGenerators.first(where: { $0.name == "IntegerGenerator" })!, 10),
        (CodeGenerators.first(where: { $0.name == "ArrayGenerator" })!, 5),
        (CodeGenerators.first(where: { $0.name == "StringGenerator" })!, 5),
        (CodeGenerators.first(where: { $0.name == "BooleanGenerator" })!, 5),
        (CodeGenerators.first(where: { $0.name == "PlainFunctionGenerator" })!, 5),
    ]

    // Add the target generator with highest weight
    essentialGenerators.append((targetGenerator, 100))

    // Special handling for generators that require specific contexts
    if ["AwaitGenerator", "ForAwaitOfLoopGenerator", "ForAwaitOfWithDestructLoopGenerator", "AsyncDisposableVariableGenerator"].contains(targetGenerator.name) {
        // Add related generators to provide the required async context
        essentialGenerators.append((CodeGenerators.first(where: { $0.name == "AsyncFunctionGenerator" })!, 500))
        essentialGenerators.append((CodeGenerators.first(where: { $0.name == "AsyncIteratorGenerator" })!, 500))
        essentialGenerators.append((CodeGenerators.first(where: { $0.name == "AsyncArrowFunctionGenerator" })!, 500))
        essentialGenerators.append((CodeGenerators.first(where: { $0.name == "AsyncGeneratorFunctionGenerator" })!, 500))
        print("Note: \(targetGenerator.name) requires async context")
    } else if ["YieldGenerator", "YieldEachGenerator"].contains(targetGenerator.name) {
        // Add related generators for generator-related contexts
        essentialGenerators.append((CodeGenerators.first(where: { $0.name == "GeneratorFunctionGenerator" })!, 500))
        essentialGenerators.append((CodeGenerators.first(where: { $0.name == "AsyncGeneratorFunctionGenerator" })!, 500))
        print("Note: \(targetGenerator.name) might require generator context")
    }
    
    let fuzzer = makeMockFuzzerWithOnlySpecificGenerators(essentialGenerators)
    
    let b = fuzzer.makeBuilder()
    b.buildPrefix()
    
    // Try multiple times to increase chances of using the target generator
    var generatedPrograms: [Program] = []
    for i in 0..<30 {
        print("Attempt \(i + 1)/30...")
        let builder = fuzzer.makeBuilder()
        builder.buildPrefix()
        
        // Try to generate code using the specific generator
        builder.build(n: 20)
        let program = builder.finalize()
        generatedPrograms.append(program)
        
        let jsCode = jsLifter.lift(program, withOptions: .includeComments)
        print("Generated JavaScript code:")
        print(jsCode)
        print("\n" + String(repeating: "=", count: 50) + "\n")
    }
}

else if args.has("--test-template") {
    guard let templateName = args["--test-template"] else {
        print("Error: --test-template requires a template name")
        exit(-1)
    }
    
    // Find the specified template
    guard let targetTemplate = ProgramTemplates.first(where: { $0.name == templateName }) else {
        print("Error: Template '\(templateName)' not found")
        print("Available templates:")
        for template in ProgramTemplates {
            print("  - \(template.name)")
        }
        exit(-1)
    }
    
    print("Testing template: \(targetTemplate.name)")
    
    // Create a mock fuzzer with default generators but forced to use specific template
    let fuzzer = makeMockFuzzer(config: Configuration(logLevel: .warning, enableInspection: true), environment: JavaScriptEnvironment())
    
    // Generate multiple programs using the target template
    for i in 0..<5 {
        print("Generating program \(i + 1)/5 using template \(templateName)...")
        
        let b = fuzzer.makeBuilder()
        
        // Directly use the target template to generate the program
        targetTemplate.generate(in: b)
        
        let program = b.finalize()
        let jsCode = jsLifter.lift(program, withOptions: .includeComments)
        
        print("Generated JavaScript code:")
        print(String(repeating: "=", count: 60))
        print(jsCode)
        print(String(repeating: "=", count: 60))
        print()
    }
}

else {
    print("Invalid option: \(args.unusedOptionals.first!)")
    exit(-1)
}
