from sys import  exit
import argparse
import os
from langchain_ollama import ChatOllama
from langchain.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate
import re
from rich.markdown import Markdown
from rich.console import Console
console = Console()
def print_md(text: str) -> None:
    console.print(Markdown(text))
def get_zeek_logs(directory: str) -> str:
    log_files = [fi for fi in os.listdir(directory) if re.search(r'\.log$', fi)]
    output = []
    for fi in log_files:
        with open(f"{os.path.join(directory,fi)}", "r") as f:
            output.append(f"{fi}\n{f.read()}")
    return "\n".join(output)

parser = argparse.ArgumentParser(description="An AI-powered tool that analyzes and summarizes Zeek logs using language models.")
parser.add_argument('-d', '--directory', required=True, help='Path to Zeek logs directory')
parser.add_argument('-u', '--url', required=True, help='The base URL of the Ollama server.')
parser.add_argument("-m", "--model", required=False, default="llama3:8b", help="The Ollama model name.")
args = parser.parse_args()
if not os.path.isdir(args.directory):
    print_md(f"# ⚠️ Error: The Directory {args.directory} was not Found!")
    exit(404)
prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template("You are an AI network analyst. Analyze the following Zeek logs and return a concise Markdown report highlighting any notable events. "
    "The report should include a main title (#), section titles (##), and bullet point lists (-) for detailing items."),
    HumanMessagePromptTemplate.from_template("Logs:\n{logs}")])
llm = ChatOllama(
    model=args.model, 
    base_url=args.url)
chain = (
    {"logs": lambda x: x["logs"]}
    | prompt
    | llm
    )
resp = chain.invoke({"logs": get_zeek_logs(args.directory)})
print_md(resp.content)