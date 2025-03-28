import asyncio
import logging
import os

from azure.identity.aio import DefaultAzureCredential
from semantic_kernel import Kernel
from semantic_kernel.agents import AzureAIAgent, AgentGroupChat
from semantic_kernel.contents import AuthorRole, ChatHistoryTruncationReducer
from semantic_kernel.functions import KernelFunctionFromPrompt
from semantic_kernel.agents.strategies import (
    KernelFunctionSelectionStrategy,
    KernelFunctionTerminationStrategy,
    TerminationStrategy
)

from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

"""
The following sample demonstrates how to use an already existing
Azure AI Agent within Semantic Kernel. This sample requires that you
have an existing agent created either previously in code or via the
Azure Portal (or CLI).
"""


# Simulate a conversation with the agent
JOB_DESCRIPTION = """ITMAGINATION helps its Clients by becoming a true extension of their software and data development capabilities. Through our readily set up, comprehensive, and self-governing teams, we let our Clients focus on their business while we make sure that their software products and data tools scale up accordingly and with outstanding quality.

We are looking for experienced team players to fill the Operations Engineer - Support Line 2 position and participate in our up-and-coming project from the chemical manufacturing industry.

You can expect:
Working with a highly skilled team of professionals
Monitoring & supporting production systems


Requirements
Min. 5 years of experience working in DevOps or SRE
Experience with CI/CD tools (e.g., Azure DevOps)
Min. 2 years working experience with Azure
Knowledge on VM’s, Appservices, App Gateways, Keyvaults, Functions,VNETs, Logicapps, Log analytic queries KQL, App insights, etc.
Experience in Azure Native monitoring tools like – Az Monitor, Appinsights, Loganalytics, Dashboards, Grafana, Prmetheus, Solarwinds, Zabbix, etc.
Ability to write SQL/Postgres queries
Understanding of all aspects of an application stack and associated technologies (Network, OS, Web, App, DB, Storage)
GDPR and PHI/PII regulations awareness
Good understanding/experience in Incident Management – Change Management and Problem Management
Excellent English skills


Benefits
Fully remote work model
Professional training programs – including Udemy and other development plans
Work with a team that’s recognized for its excellence. We’ve been featured in the Deloitte Technology Fast 50 & FT 1000 rankings. We’ve also received the Great Place To Work® certification for five years in a row"""

load_dotenv()
# Set up logging
AZURE_APP_INSIGHTS_CONNECTION_STRING = os.getenv("AZURE_APP_INSIGHTS_CONNECTION_STRING")

resource = Resource.create({ResourceAttributes.SERVICE_NAME: "Job Oppening Mapper"})


def create_kernel() -> Kernel:
    """Creates an instance of the Semantic Kernel."""
    kernel = Kernel()
    return kernel

async def main() -> None:
    async with (
        DefaultAzureCredential() as creds,
        AzureAIAgent.create_client(credential=creds) as client,
    ):
      kernen = create_kernel()

      manager_definition = await client.get_agent_definition("asst_H46WKAqAJtIGvr5S1hGqKqfA")
      reviewer_definition = await client.get_agent_definition("asst_oHmRHEfCufdamKksLlF9H95k")
      skills_definition = await client.get_agent_definition("asst_GPBPFdJxR7Vi3VdP7vZnKqch")

    manager_agent = AzureAIAgent(
        client=client,
        definition=manager_definition,
    )

    job_reviewer = AzureAIAgent(
        client=client,
        definition=reviewer_definition,
    )

    skills_agent = AzureAIAgent(
        client=client,
        definition=skills_definition,
    )


if __name__ == "__main__":
    asyncio.run(main())