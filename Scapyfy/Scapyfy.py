from dotenv import load_dotenv 
import os 
from langchain_openai import ChatOpenAI 
from langchain.tools import tool 
from scapy.all import Ether, IP, ARP, TCP, UDP, ICMP, sr, srp, send, Packet 
from scapy.packet import Raw 
import json 
from langchain.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate, MessagesPlaceholder 
from langchain_core.runnables import RunnableSerializable 
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage 
from rich.console import Console 
from rich.markdown import Markdown 
import argparse 
import sys 
console = Console() 
def print_md_report(report: str): 
    md = Markdown(report) 
    console.print(md) 
parser = argparse.ArgumentParser(description="📦 Scapyfy - A command-line AI-Powered packet crafting assistant.") 
 
group = parser.add_mutually_exclusive_group(required=True) 
group.add_argument("-p", "--prompt", type=str, help="The prompt string to use directly.") 
group.add_argument( "-f", "--file", type=str, help="Path to a file containing the prompt.") 
parser.add_argument( "-m", "--max-iter", type=int, default=3, help="Maximum number of tool-agent iterations (default: 3)") 
parser.add_argument("-t", "--api-key", type=str, help="The OpenAI API secret key. It is recommended to set this via environment variables (e.g., OPENAI_API_KEY).")
args = parser.parse_args() 
 
user_input_prompt = args.prompt 
if args.file: 
  with open(args.file) as fi: 
    user_input_prompt = fi.read() 
load_dotenv() 
if not os.getenv("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = args.api_key
if not os.environ["OPENAI_API_KEY"]: 
  print_md_report("# ⚠️ Error: The OpenAI API secret key was not found!") 
  sys.exit(404) 
 
@tool 
def send(pkt_desc: str, isEther: bool = False, wantResp: bool = True) -> str: 
    """ 
    Sends a crafted packet using Scapy based on a JSON-formatted string. 
    Parameters: 
    - pkt_desc: A JSON string describing protocol layers and their fields. 
      Example: '{"Ether": {"src": "00:11:22:33:44:55"}, "IP": {"dst": "192.168.0.1"}, "TCP": {"dport": 22, "flags": "S"}}' 
    - isEther: Whether the link layer (Ether) is used (srp instead of sr). 
    - wantResp: Whether to return the first response packet. 
    Returns: 
    - The first response Packet if wantResp is True and a response is received. 
    - None otherwise. 
    """ 
    layers = json.loads(pkt_desc) 
    pkt = None 
    for layer_name, fields in layers.items(): 
        layer_cls = globals().get(layer_name) 
        if not layer_cls: 
            raise ValueError(f"Unknown layer: {layer_name}") 
        layer = layer_cls(**fields) 
        if pkt is None: 
            pkt = layer 
        else: 
            pkt = pkt / layer 
    if isEther: 
        if wantResp: 
            answered, _ = srp(pkt, timeout=2, verbose=0)
            try: 
                return repr(answered[0][1])
            except IndexError:
                return "No answer"
        else: 
            send(pkt, verbose=0) 
            return "No answer" 
    else: 
        if wantResp: 
            answered, _ = sr(pkt, timeout=2, verbose=0) 
            try:
                return repr(answered[0][1]) 
            except IndexError:
                return "No answer"
        else: 
            send(pkt, verbose=0)
            return "No answer"
@tool 
def final_report(report: str) -> str: 
    """ 
    Submit the final report  
    """ 
    return report 
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.0) 
system_prompt = SystemMessagePromptTemplate.from_template( 
    "You are Prof. Packet Crafter, a network assistant in a lab environment. " 
    "Craft packets using available tools based on situations, Use IP layer only unless the task explicitly requires Ethernet " 
    "When writing the final report, format it in Markdown for terminal display. "  
) 
user_prompt = HumanMessagePromptTemplate.from_template( 
    "Situation:\n'''{situation}'''" 
) 
prompt = ChatPromptTemplate.from_messages([ 
    system_prompt, 
    user_prompt, 
    MessagesPlaceholder(variable_name="agent_scratchpad"), 
]) 
tools = [send, final_report] 
name2tool = {tool.name: tool.func for tool in tools}
class CustomExecutor: 
    def __init__(self, max_iterations: int) -> None: 
        self.max_iterations = max_iterations 
        self.agent: RunnableSerializable = ( 
                    {"situation": lambda x: x["situation"], 
                    "agent_scratchpad": lambda x: x.get("agent_scratchpad")} 
                    | prompt 
                    | llm.bind_tools(tools, tool_choice="any") 
                ) 
    def invoke(self, situation: str) -> str: 
        agent_scratchpad = [] 
        for _ in range(self.max_iterations): 
            tool_call = self.agent.invoke( 
                { 
                    "situation": situation, 
                    "agent_scratchpad": agent_scratchpad 
                } 
            ) 
            if not tool_call.tool_calls: 
                return "# ⚠️ Error: No tool calls from agent" 
            for tool_call in tool_call.tool_calls:
                agent_scratchpad.append(AIMessage(content="", tool_calls=[tool_call]))
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                tool_call_id = tool_call["id"]

                try:
                    tool_output = name2tool[tool_name](**tool_args)
                except Exception as e:
                    tool_output = f"Tool execution error: {e}"

                agent_scratchpad.append(ToolMessage(
                    content=str(tool_output),
                    tool_call_id=tool_call_id
                ))
                if tool_name == "final_report":
                    return tool_output
        return "# ⚠️ Error: Maximum Number of Iterations Exceeded" 
    def enter(self): 
        return self 
    def exit(self, exc_type, exc_value, traceback): 
        pass 
max_iter = args.max_iter
if not max_iter: max_iter = 3
executor = CustomExecutor(max_iterations=max_iter) 
report = executor.invoke(situation=user_input_prompt) 
print_md_report(report)
