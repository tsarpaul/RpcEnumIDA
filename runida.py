import json
import os
import csv
import shutil
import re
from time import sleep

MAX_DEPTH = 5

# CSV field names
fieldnames = ['type', 'module', 'name', 'calledby', 'calledbymodule']

# Output files for CSV
fdext = open("log-ext.csv", 'a')
fdint = open("log-int.csv", 'a')
fdrpc = open("log-rpc.csv", 'a')
csvext = csv.DictWriter(fdext, delimiter=' ', quotechar='|',
                        quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)
csvext.writeheader()
csvint = csv.DictWriter(fdint, delimiter=' ', quotechar='|',
                        quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)
csvint.writeheader()
csvrpc = csv.DictWriter(fdrpc, delimiter=' ', quotechar='|',
                        quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)
csvrpc.writeheader()

# GDL variables
node_id_re = re.compile('title: "(.*?)" ')
func_name_re = re.compile('label: "(.*?)" ')
color_re = re.compile('color: (.*?) ')
source_name_re = re.compile('sourcename: "(.*?)" ')
target_name_re = re.compile('targetname: "(.*?)" ')
EXT_color = "80"

def parse_gdl(module_path, filename="out.gdl"):
    gdl_by_node = {}
    gdl_by_func = {}

    with open(filename) as f:
        raw_lines = f.readlines()
    for line in raw_lines:
        if line.startswith('node'):
            node_id = node_id_re.search(line).group(1)
            func_name = func_name_re.search(line).group(1)
            color = color_re.search(line).group(1)
            func_type = "ExtFunction" if color == EXT_color else "IntFunction"
            gdl_by_node[node_id] = {"name": func_name, "edges": [], "type": func_type, "filename": module_path}
            gdl_by_func[func_name] = node_id
        if line.startswith('edge'):
            node_id = source_name_re.search(line).group(1)
            target_node_id = target_name_re.search(line).group(1)
            gdl_by_node[node_id]["edges"].append(target_node_id)
            
    return gdl_by_node, gdl_by_func


def parse_gdl_old(filename="out.gdl"):
    gdl_by_node = {}
    gdl_by_func = {}

    with open(filename) as f:
        raw_lines = f.readlines()
    for line in raw_lines:
        if line.startswith('node'):
            node_id = node_id_re.search(line).group(1)
            func_name = func_name_re.search(line).group(1)
            gdl_by_node[node_id] = {"func": func_name, "edges": []}
            gdl_by_func[func_name] = node_id
        if line.startswith('edge'):
            node_id = source_name_re.search(line).group(1)
            target_node_id = target_name_re.search(line).group(1)
            gdl_by_node[node_id]["edges"].append(target_node_id)
            
    return gdl_by_node, gdl_by_func
    

def parse_function_from_gdl(gdl_by_node, gdl_by_func, node_id, depth):
    func_node = gdl_by_node[node_id]
    if depth == 1:
        return {node_id: {}}
    func_name = func_node["name"]
    expanded_edges = {}
    edges = gdl_by_node[node_id]["edges"]
    for edge in edges:
        edge_node = gdl_by_node[edge]
        edge_func_name = edge_node["name"]
        # WriteCSV
        if edge_node['type'] == 'IntFunction':
            csvint.writerow({'type': 'IntFunction', 'module': edge_node["filename"].replace("\\", "/"), 'name': edge_node['name'], 'calledby': func_name, 'calledbymodule': edge_node["filename"].replace("\\", "/")})
        elif edge_node['type'] == 'ExtFunction':
            csvext.writerow({'type': 'ExtFunction', 'module': edge_node["filename"].replace("\\", "/"), 'name': edge_node['name'], 'calledby': func_name, 'calledbymodule': edge_node["filename"].replace("\\", "/")})
        else:
            raise Exception("RpcFunction called directly!")
        inner_edges = parse_function_from_gdl(gdl_by_node, gdl_by_func, edge, depth-1)
        expanded_edges.update(inner_edges)
    return {node_id: expanded_edges}


uuids = {}
uuids_by_filenames = {}
results_dir = './results'
# Sort modules into filenames and avoid duplicates
for filename in os.listdir(results_dir):
    with open(results_dir + "/" + filename) as f:
        data = json.load(f)
        
    for module in data["modules"]:
        mod_filename = module["module_filename"]
        if mod_filename == 'combase.dll':
            continue
        uuid = module["uuid"]
    
        if uuid in uuids:
            continue
        uuids[uuid] = module

        if mod_filename not in uuids_by_filenames:
            uuids_by_filenames[mod_filename] = set()
        uuids_by_filenames[mod_filename].add(uuid)

# We create this temporary directory so IDA has somewhere to create IDB files
if not os.path.exists('idbs'):
    os.mkdir('idbs')

filenames_graph = {}
for filename, file_uuids in uuids_by_filenames.items():
    file_basename = os.path.basename(filename)
    dll_path = "./idbs/{}".format(file_basename)
    shutil.copy(filename, dll_path)
    
    command = '"C:\\Program Files\\IDA 7.0\\idat64.exe" -Screategdl.py -A {}'.format(dll_path)
    os.environ['_NT_SYMBOL_PATH'] = 'srv*c:\\symbols*http://msdl.microsoft.com/download/symbols'
    os.system(command)
    sleep(5)
    
    gdl_by_node, gdl_by_func = parse_gdl(filename)
    functions_graph = {}
    for uuid in file_uuids:
        uuid_module = uuids[uuid]
        for function in uuid_module["functions"]:
            # Assign RPCFunction type to RPC functions
            try:
                node_id = gdl_by_func[function["method"]]
            except:
                print("Error finding RPCFunction {}".format(function["method"]))
                import pdb; pdb.set_trace()
                continue
            node = gdl_by_node[node_id]
            node["type"] = "RPCFunction"
            
            # Write to CSV
            csvrpc.writerow({'type': 'RpcFunction', 'module': filename.replace(
        "\\", "/"), 'name': node['name'], 'calledby': '', 'calledbymodule': ''})
            
            # Build call graph
            graph = parse_function_from_gdl(gdl_by_node, gdl_by_func, node_id, depth=MAX_DEPTH)
            functions_graph[function["method"]] = graph
    filenames_graph[filename] = functions_graph
    os.remove("out.gdl")

