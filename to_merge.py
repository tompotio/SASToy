import argparse
import ast
import sys
import os
import json
import copy

from pathlib import Path

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GRAY = "\033[90m"
BG_RED = "\033[41m\033[37m"
BG_YELLOW = "\033[43m\033[30m"

rules_path = Path(__file__).resolve().with_name("rules_function_calls.json")
with open(rules_path, "r", encoding="utf-8") as f:
  SECURITY_FUNCTION_CALLS_RULES = json.load(f)

# Taint Analysis
class PathSensitiveTaintVisitor(ast.NodeVisitor):
  """ 
  Node Visitor effectuant une Taint Analysis sensible au chemin (Path-Sensitive).
  Il clone et fusionne les états des variables lors des conditions (If/Else) pour simuler un CFG.
  """

  def __init__(self, filepath):
    self.import_map = {}  # lie les alias aux noms réelles ( ex: "pk": "pickle" avec import pickle as pk)
    self.filepath = filepath
    self.findings = set() # vulnérabilités détectées
    
    # Variables corrompues
    self.tainted_variables = set()

    self.tainted_arguments_by_func = {}  # Stocke l'index de l'argument corrompu lors d'un appel de fonction
    self.function_params_map = {}        # Stocke les noms des paramètres ( fonctions )


    # SOURCES : Origines de données potentiellement dangereuses( à modifier )
    self.SOURCES = {"input", "getenv", "environ", "read", "get", "post","request.args", "request.form", "request.json", "request.values", "request.cookies", "request.files"}
    
    self.SANITIZERS = {"basename", "urlparse", "escape", "int", "float","clean_input"}


    # SINKS : Fonctions sensibles
    self.SINKS = {
    	"pickle.loads":"Insecure Deserialization",
	"pickle.load":"Insecure Deserialization",
	"pickle.Unpickler":"Insecure Deserialization",
	"dill.loads":"Insecure Deserialization",
	"dill.load":"Insecure Deserialization",
	"dill.Unpickler":"Insecure Deserialization",
	"shelve.open":"Insecure Deserialization",
	"shelve.DbfilenameShelf":"Insecure Deserialization",
	"jsonpickle.decode":"Insecure Deserialization",
	"jsonpickle.unpickler.decode":"Insecure Deserialization",
	"jsonpickle.unpickler.Unpickler":"Insecure Deserialization",
	"unpickler.decode":"Insecure Deserialization",
	"unpickler.Unpickler":"Insecure Deserialization",
	"pandas.read_pickle":"Insecure Deserialization",
	"marshal.load":"Insecure Deserialization",
	"marshal.loads":"Insecure Deserialization",
	"loads":"Insecure Deserialization",
	"load":"Insecure Deserialization",
	"Unpickler":"Insecure Deserialization",
	"open":"Insecure Deserialization",
	"DbfilenameShelf":"Insecure Deserialization",
	"decode":"Insecure Deserialization",
	"read_pickle":"Insecure Deserialization",
	"Crypto.Hash.MD2.new":"Weak Cryptography",
	"Crypto.Hash.MD4.new":"Weak Cryptography",
	"Crypto.Hash.MD5.new":"Weak Cryptography",
	"Crypto.Hash.SHA.new":"Weak Cryptography",
	"Cryptodome.Hash.MD2.new":"Weak Cryptography",
	"Cryptodome.Hash.MD4.new":"Weak Cryptography",
	"Cryptodome.Hash.MD5.new":"Weak Cryptography",
	"Cryptodome.Hash.SHA.new":"Weak Cryptography",
	"Hash.MD2.new":"Weak Cryptography",
	"Hash.MD4.new":"Weak Cryptography",
	"Hash.MD5.new":"Weak Cryptography",
	"Hash.SHA.new":"Weak Cryptography",
	"MD2.new":"Weak Cryptography",
	"MD4.new":"Weak Cryptography",
	"MD5.new":"Weak Cryptography",
	"SHA.new":"Weak Cryptography",
	"cryptography.hazmat.primitives.hashes.MD5":"Weak Cryptography",
	"cryptography.hazmat.primitives.hashes.SHA1":"Weak Cryptography",
	"hashes.MD5":"Weak Cryptography",
	"hashes.SHA1":"Weak Cryptography",
	"MD5":"Weak Cryptography",
	"hashlib.md5": "Weak Cryptography",
        "md5": "Weak Cryptography",
	"SHA1":"Weak Cryptography",
	"Crypto.Cipher.ARC2.new":"Weak Cryptography",
	"Crypto.Cipher.ARC4.new":"Weak Cryptography",
	"Crypto.Cipher.Blowfish.new":"Weak Cryptography",
	"Crypto.Cipher.DES.new":"Weak Cryptography",
	"Crypto.Cipher.XOR.new":"Weak Cryptography",
	"Cryptodome.Cipher.ARC2.new":"Weak Cryptography",
	"Cryptodome.Cipher.ARC4.new":"Weak Cryptography",
	"Cryptodome.Cipher.Blowfish.new":"Weak Cryptography",
	"Cryptodome.Cipher.DES.new":"Weak Cryptography",
	"Cryptodome.Cipher.XOR.new":"Weak Cryptography",
	"Cipher.ARC2.new":"Weak Cryptography",
	"Cipher.ARC4.new":"Weak Cryptography",
	"Cipher.Blowfish.new":"Weak Cryptography",
	"Cipher.DES.new":"Weak Cryptography",
	"Cipher.XOR.new":"Weak Cryptography",
	"ARC2.new":"Weak Cryptography",
	"ARC4.new":"Weak Cryptography",
	"Blowfish.new":"Weak Cryptography",
	"DES.new":"Weak Cryptography",
	"XOR.new":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.algorithms.ARC4":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.algorithms.Blowfish":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.algorithms.CAST5":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.algorithms.IDEA":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.algorithms.SEED":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.algorithms.TripleDES":"Weak Cryptography",
	"algorithms.ARC4":"Weak Cryptography",
	"algorithms.Blowfish":"Weak Cryptography",
	"algorithms.CAST5":"Weak Cryptography",
	"algorithms.IDEA":"Weak Cryptography",
	"algorithms.SEED":"Weak Cryptography",
	"algorithms.TripleDES":"Weak Cryptography",
	"ARC4":"Weak Cryptography",
	"Blowfish":"Weak Cryptography",
	"CAST5":"Weak Cryptography",
	"IDEA":"Weak Cryptography",
	"SEED":"Weak Cryptography",
	"TripleDES":"Weak Cryptography",
	"cryptography.hazmat.primitives.ciphers.modes.ECB":"Weak Cryptography",
	"modes.ECB":"Weak Cryptography",
	"ECB":"Weak Cryptography",
	"new":"Weak Cryptography",
	"tempfile.mktemp":"Race Condition",
	"mktemp":"Race Condition",
	"django.utils.safestring.mark_safe":"XSS",
	"safestring.mark_safe":"XSS",
	"mark_safe":"XSS",
	"urllib.request.urlopen":"SSRF_LFI_URLLIB",
	"urllib.request.urlretrieve":"SSRF_LFI_URLLIB",
	"urllib.request.URLopener":"SSRF_LFI_URLLIB",
	"urllib.request.FancyURLopener":"SSRF_LFI_URLLIB",
	"six.moves.urllib.request.urlopen":"SSRF_LFI_URLLIB",
	"six.moves.urllib.request.urlretrieve":"SSRF_LFI_URLLIB",
	"six.moves.urllib.request.URLopener":"SSRF_LFI_URLLIB",
	"six.moves.urllib.request.FancyURLopener":"SSRF_LFI_URLLIB",
	"request.urlopen":"SSRF_LFI_URLLIB",
	"request.urlretrieve":"SSRF_LFI_URLLIB",
	"request.URLopener":"SSRF_LFI_URLLIB",
	"request.FancyURLopener":"SSRF_LFI_URLLIB",
	"urlopen":"SSRF_LFI_URLLIB",
	"urlretrieve":"SSRF_LFI_URLLIB",
	"URLopener":"SSRF_LFI_URLLIB",
	"FancyURLopener":"SSRF_LFI_URLLIB",
	"random.Random":"WEAK_PRNG",
	"random.random":"WEAK_PRNG",
	"random.randrange":"WEAK_PRNG",
	"random.randint":"WEAK_PRNG",
	"random.choice":"WEAK_PRNG",
	"random.choices":"WEAK_PRNG",
	"random.uniform":"WEAK_PRNG",
	"random.triangular":"WEAK_PRNG",
	"random.randbytes":"WEAK_PRNG",
	"random.sample":"WEAK_PRNG",
	"random.getrandbits":"WEAK_PRNG",
	"Random":"WEAK_PRNG",
	"randrange":"WEAK_PRNG",
	"randint":"WEAK_PRNG",
	"choice":"WEAK_PRNG",
	"choices":"WEAK_PRNG",
	"uniform":"WEAK_PRNG",
	"triangular":"WEAK_PRNG",
	"randbytes":"WEAK_PRNG",
	"sample":"WEAK_PRNG",
	"getrandbits":"WEAK_PRNG",
	"telnetlib.Telnet":"INSECURE_TRANSPORT",
	"Telnet":"INSECURE_TRANSPORT",
	"ftplib.FTP":"INSECURE_TRANSPORT",
	"FTP":"INSECURE_TRANSPORT",
	"ssl._create_unverified_context":"WEAK_SSL_CONTEXT",
	"_create_unverified_context":"WEAK_SSL_CONTEXT",
	"xml.etree.cElementTree.parse":"XML_XXE",
	"xml.etree.cElementTree.iterparse":"XML_XXE",
	"xml.etree.cElementTree.fromstring":"XML_XXE",
	"xml.etree.cElementTree.XMLParser":"XML_XXE",
	"xml.etree.ElementTree.parse":"XML_XXE",
	"xml.etree.ElementTree.iterparse":"XML_XXE",
	"xml.etree.ElementTree.fromstring":"XML_XXE",
	"xml.etree.ElementTree.XMLParser":"XML_XXE",
	"cElementTree.parse":"XML_XXE",
	"cElementTree.iterparse":"XML_XXE",
	"cElementTree.fromstring":"XML_XXE",
	"cElementTree.XMLParser":"XML_XXE",
	"ElementTree.parse":"XML_XXE",
	"ElementTree.iterparse":"XML_XXE",
	"ElementTree.fromstring":"XML_XXE",
	"ElementTree.XMLParser":"XML_XXE",
	"xml.sax.expatreader.create_parser":"XML_XXE",
	"expatreader.create_parser":"XML_XXE",
	"create_parser":"XML_XXE",
	"xml.dom.expatbuilder.parse":"XML_XXE",
	"xml.dom.expatbuilder.parseString":"XML_XXE",
	"expatbuilder.parse":"XML_XXE",
	"expatbuilder.parseString":"XML_XXE",
	"xml.sax.parse":"XML_XXE",
	"xml.sax.parseString":"XML_XXE",
	"xml.sax.make_parser":"XML_XXE",
	"make_parser":"XML_XXE",
	"xml.dom.minidom.parse":"XML_XXE",
	"xml.dom.minidom.parseString":"XML_XXE",
	"minidom.parse":"XML_XXE",
	"minidom.parseString":"XML_XXE",
	"xml.dom.pulldom.parse":"XML_XXE",
	"xml.dom.pulldom.parseString":"XML_XXE",
	"pulldom.parse":"XML_XXE",
	"pulldom.parseString":"XML_XXE",
	"parse":"XML_XXE",
	"parseString":"XML_XXE",
	"iterparse":"XML_XXE",
	"fromstring":"XML_XXE",
	"XMLParser":"XML_XXE",
	"cursor.execute":"SQLi",
	"execute":"SQLi",
	"raw":"SQLi",
	"text":"SQLi",
	"eval": "UNSAFE_EVAL",
	"exec": "UNSAFE_EXEC",
	"system": "COMMAND_INJECTION_OS",
	"popen": "COMMAND_INJECTION_OS",
	"os.popen":"COMMAND_INJECTION_OS",
	"run": "COMMAND_INJECTION_SUBPROCESS",
	"subprocess.run":"COMMAND_INJECTION_SUBPROCESS",
	"call": "COMMAND_INJECTION_SUBPROCESS",
	"subprocess.call":"COMMAND_INJECTION_SUBPROCESS",
	"check_output": "COMMAND_INJECTION_SUBPROCESS",
	"subprocess.check_output":"COMMAND_INJECTION_SUBPROCESS",
	"open": "PATH_TRAVERSAL_OPEN",
	"Path": "PATH_TRAVERSAL_PATHLIB",
	"pathlib.Path":"PATH_TRAVERSAL_PATHLIB",
	"Path.read_text":"PATH_TRAVERSAL_PATHLIB",
	"Path.read_bytes":"PATH_TRAVERSAL_PATHLIB",
	"read_text": "PATH_TRAVERSAL_PATHLIB",
	"read_bytes": "PATH_TRAVERSAL_PATHLIB",
	"request.get":"SSRF",
	"requests.get":"SSRF",
	"get":"SSRF",
	"request.args":"Authentication / Authorization",
	"args":"Authentication / Authorization",
	"request.form":"Authentication / Authorization",
	"form":"Authentication / Authorization",
	"request.json":"Authentication / Authorization",
	"json":"Authentication / Authorization",
	"request.headers":"Authentication / Authorization",
	"headers":"Authentication / Authorization",
	"render_template_string":"XSS / SSTI",
	"flask.render_template_string":"XSS / SSTI",
	"Template":"XSS / SSTI",
	"markupsafe.Markup":"XSS / UNSAFE HTML",
	"flask.Markup":"XSS / UNSAFE HTML",
	"Markup":"XSS / UNSAFE HTML",
	"file.save":"File Upload Vulnerability",
	"save":"File Upload Vulnerability",
	"flask.redirect":"Open Redirect",
	"redirect":"Open Redirect"
    }

  def _resolve_attribute_chain(self, node):
    """
    Reconstruit récursivement la chaîne complète d'un attribut.
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base_name = self._resolve_attribute_chain(node.value)
        if base_name:
            return f"{base_name}.{node.attr}"
    return None

  def _resolve_full_name(self, node):
    """ 
    Reconstruit le nom de fonction d'après les imports ( ex: 'pk.loads' -> 'pickle.loads')
    """
    if isinstance(node, ast.Name):
        return self.import_map.get(node.id, node.id)
    elif isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            base = self.import_map.get(node.value.id, node.value.id)
            return f"{base}.{node.attr}"
    return None

  def _check_expression_taint(self, node):
    """ Évalue récursivement si une expression de l'AST contient ou propage une teinte. 
        Retourne True si l'expression provient d'une source ou d'une variable corrompu
    """
    if node is None:
      return False

    # Cas 1 : Appel de fonction ou de méthode
    if isinstance(node, ast.Call):
      # Reconstruit le chemin d'appel complet (ex: ["request", "environ", "get"])
      full_call_name = self._resolve_attribute_chain(node.func) or self._resolve_full_name(node.func)
      
      if full_call_name:
        # On découpe la chaîne pour vérifier si un des segments est une SOURCE
        # Exemple : pour "request.environ.get", les segments sont ["request", "environ", "get"]
        parts = full_call_name.split('.')
        if any(source in parts for source in self.SOURCES):
          return True
      # si c'est une méthode appelée sur un objet (ex: variable.encode())
      # On vérifie si l'objet de base (node.func.value) est lui-même corrompu
      if isinstance(node.func, ast.Attribute):
        if self._check_expression_taint(node.func.value):
          return True
          
      # même si un seul paramètre de la fonction est corrompu, l'appel est risqué
      return any(self._check_expression_taint(arg) for arg in node.args)


    # Cas 2 : cas simple : vérifie juste si la variable est dans le set des variables corrompues
    # Exemple : x (si 'x' est déjà présent dans self.tainted_variables)
    if isinstance(node, ast.Name):
      return node.id in self.tainted_variables

    # Cas 3 : Opération binaire : propage la teinte si l'un des 2 côté est corrompu 
    # exemples : concaténation de chaînes / SQLi : "SELECT * FROM users WHERE id = " + user_input
    if isinstance(node, ast.BinOp):
      # La teinte se propage si l'opérande gauche OU l'opérande droit est compromis
      return self._check_expression_taint(node.left) or self._check_expression_taint(node.right)

    # cas 4 : Cela concerne les F-string : si une variable est corrompue alors tout est corrompue
    # Exemple : f"La commande est : {commande_utilisateur}"
    if isinstance(node, ast.JoinedStr):
      for value in node.values:
        if isinstance(value, ast.FormattedValue) and self._check_expression_taint(value.value):
          return True
      return False

    # Cas 5 & 6 : Accès à un attribut ou un index (ex: sys.argv[1] ou request.args['id'])
    if isinstance(node, (ast.Subscript, ast.Attribute)):
      full_path = self._resolve_attribute_chain(node)
      if full_path:
        # on vérifie si une source ou sys.argv est contenue dans le chemin complet
        if any(source in full_path for source in self.SOURCES) or "sys.argv" in full_path:
          return True
      
      # Si ce n'est pas une source directe, on vérifie récursivement l'objet de base
      return self._check_expression_taint(node.value)


    # Cas 7 : Liste (ex: [ord(c) for c in variable_corrompue])
    if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
      for generator in node.generators:
        # Si l'itérable source de la boucle (ex: xml_payload) est corrompu
        if self._check_expression_taint(generator.iter):
          return True
    #cas 8 : opération unaire (ex: cmd = "ping" + (-user_input)
    if isinstance(node, ast.UnaryOp):
      return self._check_expression_taint(node.operand)
      
    # cas 9 : expressions ternaires (ex: data = user_input if condition else "safe_string")
    if isinstance(node, ast.IfExp):
      return self._check_expression_taint(node.body) or self._check_expression_taint(node.orelse)

    # cas 10 : structures de données : Si une variable corrompue est injecté à l'intérieur d'un tableau
    # ou d'un Dico alors la structure est corrompue
    # ex : params = [1, 2, user_input] puis execute(params)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
      return any(self._check_expression_taint(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
      # On vérifie les clés ET les valeurs (au cas où une clé injectée soit dangereuse)
      return any(self._check_expression_taint(k) for k in node.keys if k is not None) or any(self._check_expression_taint(v) for v in node.values)


    return False


  def visit_FunctionDef(self, node):
    """
    Permet de propager l'état de corruption des arguments à travers le scope local de la fonction
    """
    # Enregistrer l'ordre et le nom des arguments de cette fonction
    params = [arg.arg for arg in node.args.args]
    self.function_params_map[node.name] = params
    
    # Sauvegarde du scope global / des variables compromises
    old_tainted = copy.deepcopy(self.tainted_variables)
    
    # Si la fonction a été appelée ailleurs avec un argument compromis 
    # Alors on ajoute le paramètre correspondant dans notre nouveau set de variables corrompues
    if node.name in self.tainted_arguments_by_func:
        for idx in self.tainted_arguments_by_func[node.name]:
            if idx < len(params):
                self.tainted_variables.add(params[idx])

    # Parcourir le corps de la fonction normalement
    for stmt in node.body:
        self.visit(stmt)
        
    # On retourne au scope global après la sortie de la fonction
    self.tainted_variables = old_tainted
    
  def visit_If(self, node):
    """
    Simule le CFG pour une structure conditionnelle
    Et purifie le flux en présence de filtres 
    """
    condition_code = ""
    try:
        condition_code = ast.unparse(node.test)
    except Exception:
        pass
    
    # Si la condition check activement un hôte ou un nom de domaine, on considère que le développeur valide l'entrée ( check anti-SSRF )
    # et donc on purifie les variables liées aux urls pour éviter des faux positif 
    if "hostname" in condition_code or "domain" in condition_code:
        # On nettoie TOUTES les variables liées à des inputs/urls dans le scope actuel
        for var in list(self.tainted_variables):
            if "url" in var or "input" in var or "data" in var or "path" in var:
                self.tainted_variables.remove(var)

    # État purifié qui sert maintenant de socle de référence
    initial_taint = copy.deepcopy(self.tainted_variables)

    # 1. Analyse de la branche IF
    self.tainted_variables = copy.deepcopy(initial_taint)
    for stmt in node.body:
      self.visit(stmt)
    taint_branch_if = copy.deepcopy(self.tainted_variables)

    # 2. Analyse de la branche ELSE
    self.tainted_variables = copy.deepcopy(initial_taint)
    for stmt in node.orelse:
      self.visit(stmt)
    taint_branch_else = copy.deepcopy(self.tainted_variables)

    # 3. Fusion des chemins (CFG Merge)
    self.tainted_variables = initial_taint.union(taint_branch_if).union(taint_branch_else)


  def visit_Assign(self, node):
    """ Met à jour l'état actuel de la teinte de chaque variable -> exemple : x = y
        - On ajoute x si la valeur y est corrompue
        - On supprime x si elle reçoit ensuite une valeur saine
    """
    is_tainted = self._check_expression_taint(node.value)
    
    # détection des sanitizers
    if isinstance(node.value, ast.Call):
        # extraction du nom de la fonction ( ex : x = escape_html(user_input))
        func_name = node.value.func.attr if isinstance(node.value.func, ast.Attribute) else (node.value.func.id if isinstance(node.value.func, ast.Name) else None)
        
        if func_name in self.SANITIZERS:
            is_tainted = False # La variable reçoit une valeur propre
    for target in node.targets:
      if isinstance(target, ast.Name):
        if is_tainted:
          # la variable cible est contaminé
          self.tainted_variables.add(target.id)
        else:
          # Purifie une variable si elle est redéfinie de manière sûre
          if target.id in self.tainted_variables:
            self.tainted_variables.remove(target.id)
    self.generic_visit(node)

  def visit_With(self, node):
    """
    Cela concerne les blocs de type : "with...as..."
    Si l'expression source est compromise ( ex : PATH_TRAVERSAL : chemin de fichier fourni par l'utilisateur )
    alors la variable qui récupère ce flux devient elle aussi compromise
    """
    for item in node.items:
      if item.optional_vars and isinstance(item.optional_vars, ast.Name):
        if self._check_expression_taint(item.context_expr):
          self.tainted_variables.add(item.optional_vars.id)
    self.generic_visit(node)


  def visit_Call(self, node):
    """
    Analyse les appels de fonctions et de méthodes (ex: subprocess.Popen, hmac.new, etc.).
    - Propage la teinte vers les paramètres des fonctions personnalisées 
    - valide si l'appel constitue une vulnérabilité
    """
    full_func_name = self._resolve_full_name(node.func)
    func_name = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else None)

    is_custom_function = func_name in self.function_params_map

    # 1. Sert à propager la teinte dans la fonction
    if is_custom_function:
        is_method = isinstance(node.func, ast.Attribute)
        for idx, arg in enumerate(node.args):
            # Si l'argument passé à la fonction contient une teinte (donnée corrompue)
            if self._check_expression_taint(arg):
                if func_name not in self.tainted_arguments_by_func:
                    self.tainted_arguments_by_func[func_name] = []
                stored_idx = idx + 1 if is_method else idx
                if stored_idx not in self.tainted_arguments_by_func[func_name]:
                    self.tainted_arguments_by_func[func_name].append(stored_idx)
                
    # 2. Résolution du Sink (Uniquement si ce n'est pas une fonction personnalisée du projet)
    rule_key = None
    if not is_custom_function:
         # Reconstruit la chaîne complète (ex: "requests.get" ou "os.system")
        resolved_name = self._resolve_attribute_chain(node.func) or full_func_name or func_name
        
        if resolved_name:
            # Étape A : Correspondance exacte immédiate (La plus sûre)
            rule_key = self.SINKS.get(resolved_name)
            
            # Étape B : Si pas de correspondance exacte, correspondance sémantique de fin de chaîne
            if not rule_key:
                for sink_path, flaw in self.SINKS.items():
                    # On vérifie si l'appel se termine par le puits ou si le puits se termine par l'appel
                    if resolved_name.endswith(sink_path) or sink_path.endswith(resolved_name):
                        if "urlparse" in resolved_name:
                            continue
                        if resolved_name.endswith(".get") and "requests" not in resolved_name:
                            continue
                        # anti faux-positifs (comme 'bytes')
                        # exemple utilisation de bytes() mais le scanner voit ça comme une weak_cryptographie -> erreur
                        if resolved_name in ["new", "text", "open", "bytes"] and resolved_name != sink_path:
                            continue
                        
                        rule_key = flaw
                        break


    # 3. Levée d'alertes contextuelle
    if rule_key:
      # Validation de la configuration de 'subprocess'
      # i.e : ne exécution de commande n'est critique (Command Injection) que si l'interpréteur de commandes (shell) est activé.
      if rule_key == "COMMAND_INJECTION_SUBPROCESS":
          has_shell_true = False
          for kw in node.keywords:
              if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                  has_shell_true = True
          if not has_shell_true:
              rule_key = None # Ce n'est pas une faille car shell=False (ou absent) !

      # conformité cryptographique (HMAC)
      if rule_key == "Weak Cryptography" and resolved_name == "hmac.new":
          is_secure_algo = any("sha256" in self._resolve_attribute_chain(arg) or "sha256" in getattr(arg, 'id', '') for arg in node.args if arg)
          for kw in node.keywords:
              if kw.arg == "digestmod" and "sha256" in (self._resolve_attribute_chain(kw.value) or ""):
                  is_secure_algo = True
          if is_secure_algo:
              rule_key = None # Algorithme robuste, on annule l'alerte !

      # Classification des vulnérabilités
      # certaines dépendes d'une entrée utilisateur potentiellement malveillantes et de fonctions dangereuses
      # d'autres dépendes uniquement des algos : MD5 ( faible / collision ) 
      if rule_key:
          if rule_key in ["Weak Cryptography", "WEAK_SSL_CONTEXT", "Race Condition", "WEAK_PRNG", "INSECURE_TRANSPORT"]:
              alerte = (self.filepath, node.lineno, rule_key, f"Utilisation dangereuse de '{resolved_name}'")
              self.findings.add(alerte)
          else:
              is_tainted_call = any(self._check_expression_taint(arg) for arg in node.args)
              if not is_tainted_call and isinstance(node.func, ast.Attribute):
                  is_tainted_call = self._check_expression_taint(node.func.value)

              if is_tainted_call:
                  alerte = (self.filepath, node.lineno, rule_key, f"Faille détectée via '{resolved_name}'. L'argument dépend d'une entrée utilisateur non nettoyée.")
                  self.findings.add(alerte)


    self.generic_visit(node)





class HardcodedSecretVisitor(ast.NodeVisitor):
  """ Node Visitor pour détecter les secrets codés en dur dans le code source. """


class SqlInjectionVisitor(ast.NodeVisitor):
  """ Node Visitor pour détecter les vulnérabilités d'injection SQL dans le code source. """


def get_python_files(target_path, recursive=False):
  if os.path.isfile(target_path) and target_path.endswith(".py"):
    return [target_path]
  if os.path.isdir(target_path):
    python_files = []
    if recursive:
      for root, dirs, files in os.walk(target_path):
        for filename in files:
          if filename.endswith(".py"):
            python_files.append(os.path.join(root, filename))
    else:
      for filename in os.listdir(target_path):
        if filename.endswith(".py"):
          full_path = os.path.join(target_path, filename)
          if os.path.isfile(full_path):
            python_files.append(full_path)
    return python_files
  return []



def parse_python_file(file):
  try: 
    with open(file, "r", encoding="utf-8") as f:
      source_code = f.read()
      return ast.parse(source_code)
  except Exception as e:
    print(f"[!] Erreur lors de l'analyse du fichier {file}: {e}")
    return None

def get_code_line(filepath, lineno):
    """ Récupère et nettoie la ligne de code exacte à partir du fichier source """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if 0 < lineno <= len(lines):
                return lines[lineno - 1].strip()
    except Exception:
        pass
    return "Code source indisponible"
  
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Analyseur statique de code source (AST + Pseudo-CFG).")
  parser.add_argument("target", type=str, help="Chemin du fichier .py ou du dossier à analyser")
  parser.add_argument("-r", "--recursive", action="store_true", help="Analyser de manière récursive")

  args = parser.parse_args()
  files_to_scan = get_python_files(args.target, recursive=args.recursive)



  print(f"\n{BOLD}{CYAN}[*]{RESET} Nombre de fichier(s) analysé(s) : {BOLD}{len(files_to_scan)}{RESET}")

  # Variables pour le résumé statistique final
  total_vulnerabilities = 0
  critical_count = 0
  warning_count = 0

  for file in files_to_scan:
    tree = parse_python_file(file)
    if tree is not None:
      visitor = PathSensitiveTaintVisitor(file)
      visitor.visit(tree)
      visitor.visit(tree)
      
      if visitor.findings:
          print(f"\n{BOLD}{CYAN}[+]{RESET} {BOLD}CIBLE : {file}{RESET}")
          print(f"{GRAY}─" * 70 + f"{RESET}")
          
          # Tri chronologique par ligne
          sorted_findings = sorted(list(visitor.findings), key=lambda x: x[1])
          
          for file_path, line, rule_key, details in sorted_findings:
              total_vulnerabilities += 1
              
              # Détermination de la sévérité et des couleurs
              if rule_key in ["WEAK_PRNG", "Weak Cryptography", "WEAK_SSL_CONTEXT"]:
                  severity = "WARNING"
                  badge = f"{BG_YELLOW} {severity} {RESET}"
                  color = YELLOW
                  warning_count += 1
              else:
                  severity = "CRITICAL"
                  badge = f"{BG_RED} {severity} {RESET}"
                  color = RED
                  critical_count += 1
              
              # Extraction de la ligne de code réelle
              source_line = get_code_line(file_path, line)
              
              # Bloc d'affichage complet style linter moderne
              print(f"  {badge} {BOLD}{color}[{rule_key}]{RESET} à la ligne {BOLD}{line}{RESET}")
              print(f"  {GRAY}│   Code : {RESET}{CYAN}{source_line}{RESET}")
              print(f"  {GRAY}└── Détail : {RESET}{details}\n")
      else:
          print(f"\n{BOLD}{GREEN}[+] CIBLE : {file}{RESET}")


  # RÉSUMÉ STATISTIQUE GLOBAL (Le grand manque comblé !)
  print(f"{GRAY}═" * 70 + f"{RESET}")
  print(f"{BOLD}{CYAN}[+] BILAN GLOBAL DE L'ANALYSE :{RESET}")
  print(f"  • Fichiers scannés : {BOLD}{len(files_to_scan)}{RESET}")
  print(f"  • Total de vulnérabilités trouvées : {BOLD}{total_vulnerabilities}{RESET}")
  
  if total_vulnerabilities > 0:
      print(f"    ├─ {RED}Critiques (Flux corrompus) : {BOLD}{critical_count}{RESET}")
      print(f"    └─ {YELLOW}Avertissements (Config faible) : {BOLD}{warning_count}{RESET}")
      
  else:
      print(f"\n{BOLD}{GREEN}[✅] SUCCÈS : Aucune(s) vulnérabilité(s) détectée(s) {RESET}\n")