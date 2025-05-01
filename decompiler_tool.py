import ast
import marshal
import os
import re
import sys
import base64
import zlib
import binascii
import inspect
import types
import logging
import traceback
import io
from typing import List, Dict, Any, Set, Optional, Tuple, Union

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DecompilerTool")

class BytecodeDumper:
    """Class for finding and dumping encoded bytecode blobs from Python files"""
    
    ENCODING_PATTERNS = [
        # Marshal encoded patterns
        (r"marshal\.loads\((.*?)\)", "marshal"),
        # Base64 patterns
        (r"base64\.b64decode\((.*?)\)", "base64"),
        # Zlib compressed patterns
        (r"zlib\.decompress\((.*?)\)", "zlib"),
        # Combined patterns (base64 + zlib)
        (r"zlib\.decompress\(base64\.b64decode\((.*?)\)\)", "zlib+base64"),
        # Custom encoding functions (common patterns)
        (r"__decode\((.*?)\)", "custom_decode"),
        (r"decode\((.*?)\)", "custom_decode"),
        (r"eval\(compile\((.*?),.*?,.*?\)\)", "eval_compile"),
        # Lambda expressions with encoding
        (r"lambda[^:]*:[^(]*\((.*?)\)", "lambda_expr"),
        # Exec with encoded content
        (r"exec\((.*?)\)", "exec_block")
    ]
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.found_bytecode_count = 0
        self.decoded_items = []
    
    def extract_bytecode_from_source(self, source_code: str) -> List[Tuple[str, str, Any]]:
        """Extract potential bytecode objects from source code"""
        extracted_items = []
        
        # Try with regex patterns first
        for pattern, encoding_type in self.ENCODING_PATTERNS:
            matches = re.finditer(pattern, source_code, re.DOTALL)
            for match in matches:
                blob = match.group(1)
                extracted_items.append((encoding_type, blob, None))
        
        return extracted_items
    
    def try_parse_blob(self, blob_str: str) -> Any:
        """Try to parse a string blob into an actual Python object"""
        # Remove quotes if present
        if (blob_str.startswith('"') and blob_str.endswith('"')) or \
           (blob_str.startswith("'") and blob_str.endswith("'")):
            blob_str = blob_str[1:-1]
        
        # Try several parsing approaches
        try:
            # Try evaluating as a Python expression
            return eval(blob_str)
        except:
            try:
                # Try as raw string with escape characters
                return eval(f'"""{blob_str}"""')
            except:
                try:
                    # Try as a hex string
                    if blob_str.startswith("b'\\x") or blob_str.startswith('b"\\x'):
                        return eval(blob_str)
                except:
                    pass
        return None
    
    def try_decode_bytecode(self, encoding_type: str, blob_data: Any) -> Tuple[bool, Any, str]:
        """Try to decode the bytecode using the detected encoding method"""
        decoded = None
        error_msg = ""
        
        try:
            if encoding_type == "marshal":
                if isinstance(blob_data, bytes):
                    decoded = marshal.loads(blob_data)
                else:
                    error_msg = "Expected bytes for marshal.loads"
                    
            elif encoding_type == "base64":
                if isinstance(blob_data, (str, bytes)):
                    decoded = base64.b64decode(blob_data)
                else:
                    error_msg = "Expected string or bytes for base64.b64decode"
                    
            elif encoding_type == "zlib":
                if isinstance(blob_data, bytes):
                    decoded = zlib.decompress(blob_data)
                else:
                    error_msg = "Expected bytes for zlib.decompress"
                    
            elif encoding_type == "zlib+base64":
                if isinstance(blob_data, (str, bytes)):
                    b64_decoded = base64.b64decode(blob_data)
                    decoded = zlib.decompress(b64_decoded)
                else:
                    error_msg = "Expected string or bytes for zlib+base64"
                    
            elif encoding_type == "custom_decode" or encoding_type == "exec_block":
                # Try various decoding methods
                if isinstance(blob_data, bytes):
                    # Try as marshal
                    try:
                        decoded = marshal.loads(blob_data)
                    except:
                        pass
                    
                    # Try as base64
                    if decoded is None:
                        try:
                            decoded = base64.b64decode(blob_data)
                        except:
                            pass
                            
                    # Try as zlib
                    if decoded is None:
                        try:
                            decoded = zlib.decompress(blob_data)
                        except:
                            pass
                            
            elif encoding_type == "eval_compile" or encoding_type == "lambda_expr":
                # Specific handling for compiled code objects
                if isinstance(blob_data, types.CodeType):
                    decoded = blob_data
                elif isinstance(blob_data, bytes):
                    try:
                        decoded = marshal.loads(blob_data)
                    except:
                        pass
            
            # Add more encoding types as needed
            
            if decoded is None and error_msg == "":
                error_msg = f"Unable to decode {encoding_type} data"
            
            return decoded is not None, decoded, error_msg
            
        except Exception as e:
            error_msg = f"Error decoding {encoding_type}: {str(e)}"
            return False, None, error_msg
    
    def decompile_code_object(self, code_obj: types.CodeType, 
                             output_file_prefix: str, 
                             depth: int = 0,
                             max_depth: int = 10) -> str:
        """Decompile a code object to Python source"""
        if depth > max_depth:
            return f"# Maximum recursion depth ({max_depth}) reached\n"
            
        if not isinstance(code_obj, types.CodeType):
            return f"# Not a code object: {type(code_obj)}\n"
        
        try:
            # For Python 3.9+, we'll use a simpler approach since uncompyle6 is not compatible
            decompiled_code = f"# Code object info:\n"
            decompiled_code += f"# - co_name: {code_obj.co_name}\n"
            decompiled_code += f"# - co_filename: {code_obj.co_filename}\n"
            decompiled_code += f"# - co_firstlineno: {code_obj.co_firstlineno}\n"
            
            # Display code object attributes
            decompiled_code += f"\n# Code object attributes:\n"
            for attr in dir(code_obj):
                if attr.startswith('co_') and not attr.startswith('co_code'):
                    try:
                        value = getattr(code_obj, attr)
                        if isinstance(value, (list, tuple)) and len(value) > 20:
                            decompiled_code += f"# - {attr}: {str(value)[:100]}...(truncated)\n"
                        else:
                            decompiled_code += f"# - {attr}: {value}\n"
                    except:
                        pass
            
            # Display constants (which might contain nested code objects)
            decompiled_code += "\n# Constants:\n"
            for i, const in enumerate(code_obj.co_consts):
                if isinstance(const, types.CodeType):
                    decompiled_code += f"# [{i}] Nested code object: {const.co_name}\n"
                else:
                    try:
                        # Truncate large constants
                        const_str = str(const)
                        if len(const_str) > 100:
                            const_str = const_str[:100] + "...(truncated)"
                        decompiled_code += f"# [{i}] {type(const).__name__}: {const_str}\n"
                    except:
                        decompiled_code += f"# [{i}] {type(const).__name__}: <unprintable>\n"
            
            # Display bytecode instructions in a human-readable format
            decompiled_code += "\n# Bytecode instructions:\n"
            try:
                import dis
                bytecode_output = io.StringIO()
                dis.dis(code_obj, file=bytecode_output)
                decompiled_code += "# " + bytecode_output.getvalue().replace('\n', '\n# ')
            except:
                decompiled_code += "# (Could not disassemble bytecode)\n"
                
            # Process nested code objects
            nested_code = ""
            for const in code_obj.co_consts:
                if isinstance(const, types.CodeType):
                    nested_code += f"\n# --- Nested function: {const.co_name} (depth: {depth+1}) ---\n"
                    nested_code += self.decompile_code_object(
                        const, 
                        f"{output_file_prefix}_nested_{const.co_name}", 
                        depth + 1,
                        max_depth
                    )
                    
            # If nested code found, save it
            if nested_code:
                nested_file_path = os.path.join(self.output_dir, f"{output_file_prefix}_nested_functions.py")
                with open(nested_file_path, 'w') as f:
                    f.write(nested_code)
                decompiled_code += f"\n# Nested functions saved to: {nested_file_path}\n"
                
            return decompiled_code
            
        except Exception as e:
            logger.error(f"Error during decompilation: {str(e)}")
            traceback.print_exc()
            return f"# Decompilation failed: {str(e)}\n"
    
    def save_decompiled_code(self, decompiled_code: str, output_file_prefix: str, 
                           encoding_type: str, index: int) -> str:
        """Save decompiled code to a file"""
        filename = f"{output_file_prefix}_{encoding_type}_{index}.py"
        file_path = os.path.join(self.output_dir, filename)
        
        with open(file_path, 'w') as f:
            f.write(decompiled_code)
            
        logger.info(f"Saved decompiled code to {file_path}")
        return file_path
    
    def save_raw_bytecode(self, bytecode: bytes, output_file_prefix: str, 
                        encoding_type: str, index: int) -> str:
        """Save raw bytecode to a file"""
        filename = f"{output_file_prefix}_{encoding_type}_{index}.pyc"
        file_path = os.path.join(self.output_dir, filename)
        
        with open(file_path, 'wb') as f:
            # Write proper pyc header for Python 3.x
            f.write(b'\x42\x0d\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')  # Header
            f.write(bytecode)
            
        logger.info(f"Saved raw bytecode to {file_path}")
        return file_path
    
    def save_hex_dump(self, data: bytes, output_file_prefix: str, 
                    encoding_type: str, index: int) -> str:
        """Save hex dump of binary data to a file"""
        filename = f"{output_file_prefix}_{encoding_type}_{index}_hexdump.txt"
        file_path = os.path.join(self.output_dir, filename)
        
        with open(file_path, 'w') as f:
            # Create a formatted hex dump
            hex_dump = ""
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_line = ' '.join(f"{b:02x}" for b in chunk)
                ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hex_dump += f"{i:08x}  {hex_line:<48}  |{ascii_line}|\n"
            f.write(hex_dump)
            
        logger.info(f"Saved hex dump to {file_path}")
        return file_path
    
    def generate_summary_report(self, source_file: str) -> Tuple[str, List[str]]:
        """Generate a summary report of all findings"""
        report = f"=== Malware Analysis Report for {source_file} ===\n\n"
        report += f"Total bytecode blobs found: {self.found_bytecode_count}\n\n"
        
        extracted_files = []
        
        for i, item in enumerate(self.decoded_items):
            encoding_type, is_code_object, file_paths = item
            report += f"[{i+1}] Encoded data ({encoding_type}):\n"
            
            for path_type, path in file_paths.items():
                report += f"  - {path_type}: {os.path.basename(path)}\n"
                extracted_files.append(path)
                
            report += "\n"
            
        # Save the report
        report_path = os.path.join(self.output_dir, "analysis_report.txt")
        with open(report_path, 'w') as f:
            f.write(report)
            
        extracted_files.append(report_path)
        return report_path, extracted_files


def analyze_python_script(file_path: str, output_dir: str = "./decompiled_payloads") -> Tuple[str, List[str]]:
    """
    Analyze a Python script for encoded/obfuscated content
    
    Args:
        file_path: Path to the Python file to analyze
        output_dir: Directory to store outputs
        
    Returns:
        Tuple of (report_path, list_of_extracted_files)
    """
    logger.info(f"Analyzing file: {file_path}")
    
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Initialize bytecode dumper
    dumper = BytecodeDumper(output_dir)
    
    try:
        # Read the source file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
            
        # Get base filename (without extension)
        base_filename = os.path.splitext(os.path.basename(file_path))[0]
        
        # Extract potential bytecode objects
        extracted_items = dumper.extract_bytecode_from_source(source_code)
        logger.info(f"Found {len(extracted_items)} potential encoded items")
        
        # Process each item
        for i, (encoding_type, blob_str, _) in enumerate(extracted_items):
            logger.info(f"Processing item {i+1}: {encoding_type}")
            
            # Try to parse the blob
            blob_data = dumper.try_parse_blob(blob_str)
            if blob_data is None:
                logger.warning(f"Failed to parse blob: {blob_str[:50]}...")
                continue
                
            # Try to decode the bytecode
            success, decoded, error = dumper.try_decode_bytecode(encoding_type, blob_data)
            if not success:
                logger.warning(f"Failed to decode: {error}")
                continue
                
            # Increment bytecode count
            dumper.found_bytecode_count += 1
            
            # Prepare file paths
            output_prefix = f"{base_filename}_item{i+1}"
            file_paths = {}
            
            # Handle code objects
            is_code_object = isinstance(decoded, types.CodeType)
            
            if is_code_object:
                # Decompile the code object
                decompiled_code = dumper.decompile_code_object(decoded, output_prefix)
                file_paths['decompiled'] = dumper.save_decompiled_code(
                    decompiled_code, output_prefix, encoding_type, i
                )
                
                # Save raw bytecode
                marshalled = marshal.dumps(decoded)
                file_paths['bytecode'] = dumper.save_raw_bytecode(
                    marshalled, output_prefix, encoding_type, i
                )
                
            # For any binary data, save a hex dump
            if isinstance(decoded, bytes):
                file_paths['hex_dump'] = dumper.save_hex_dump(
                    decoded, output_prefix, encoding_type, i
                )
                
                # Try to decode as string and save
                try:
                    string_data = decoded.decode('utf-8', errors='ignore')
                    string_file = os.path.join(output_dir, f"{output_prefix}_{encoding_type}_{i}_string.txt")
                    with open(string_file, 'w') as f:
                        f.write(string_data)
                    file_paths['string'] = string_file
                except:
                    pass
            
            # Add to decoded items
            dumper.decoded_items.append((encoding_type, is_code_object, file_paths))
            
        # Generate report
        return dumper.generate_summary_report(file_path)
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        traceback.print_exc()
        
        # Generate error report
        error_report = f"=== ERROR REPORT ===\n\n"
        error_report += f"Failed to analyze file: {file_path}\n"
        error_report += f"Error: {str(e)}\n\n"
        error_report += f"Traceback:\n{traceback.format_exc()}\n"
        
        report_path = os.path.join(output_dir, "error_report.txt")
        with open(report_path, 'w') as f:
            f.write(error_report)
            
        return report_path, [report_path]


if __name__ == "__main__":
    # Simple CLI for testing
    if len(sys.argv) < 2:
        print("Usage: python decompiler_tool.py <python_file_to_analyze>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    report_path, extracted_files = analyze_python_script(file_path)
    
    print(f"\nAnalysis complete! Report saved to: {report_path}")
    print(f"Files extracted: {len(extracted_files)}")
