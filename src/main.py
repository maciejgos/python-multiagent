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

class ApprovalTerminationStrategy(TerminationStrategy):
    """A strategy for determining when an agent should terminate."""

    async def should_agent_terminate(self, agent, history):
        """Check if the agent should terminate."""
        return "approved" in history[-1].content.lower()

def create_kernel() -> Kernel:
    """Creates an instance of the Semantic Kernel."""
    kernel = Kernel()
    return kernel

def set_up_tracing():
    from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import set_tracer_provider

    # Initialize a trace provider for the application. This is a factory for creating tracers.
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(AzureMonitorTraceExporter(connection_string=AZURE_APP_INSIGHTS_CONNECTION_STRING))
    )
    # Sets the global default tracer provider
    set_tracer_provider(tracer_provider)


def set_up_logging():
    from azure.monitor.opentelemetry.exporter import AzureMonitorLogExporter
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

    # Create and set a global logger provider for the application.
    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(AzureMonitorLogExporter(connection_string=AZURE_APP_INSIGHTS_CONNECTION_STRING))
    )
    # Sets the global default logger provider
    set_logger_provider(logger_provider)

    # Create a logging handler to write logging records, in OTLP format, to the exporter.
    handler = LoggingHandler()
    # Attach the handler to the root logger. `getLogger()` with no arguments returns the root logger.
    # Events from all child loggers will be processed by this handler.
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

async def create_agent(client, agent_id) -> AzureAIAgent:
    """Creates an agent using the Azure AI Agent client."""
    # Create an agent using the Azure AI Agent client
    agent = AzureAIAgent(
        client =client,
        definition = await client.agents.get_agent(agent_id)
    )
    return agent

async def main() -> None:
    async with (
        DefaultAzureCredential() as creds,
        AzureAIAgent.create_client(credential=creds) as client,
    ):
        if AZURE_APP_INSIGHTS_CONNECTION_STRING:
            set_up_tracing()
            set_up_logging()

        # Create agents
        manager_agent = await create_agent(client, "asst_H46WKAqAJtIGvr5S1hGqKqfA")
        job_reviewer = await create_agent(client, "asst_oHmRHEfCufdamKksLlF9H95k")
        skills_agent = await create_agent(client, "asst_GPBPFdJxR7Vi3VdP7vZnKqch")

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("main"):
            agents = [
                manager_agent,
                job_reviewer,
                skills_agent,
            ]
    
        # Create a kernel instance
        kernel = create_kernel()

        # Create a history reducer to limit tokens consumption
        history_reducer = ChatHistoryTruncationReducer(target_count=5)

        chat = AgentGroupChat(
            agents=[manager_agent, job_reviewer, skills_agent],
            termination_strategy=ApprovalTerminationStrategy(agents=[manager_agent], maximum_iterations=10),
        )

        try:
            await chat.add_chat_message(JOB_DESCRIPTION)
            print(f"# {AuthorRole.USER}: '{JOB_DESCRIPTION}'")
            # Invoke the chat
            async for content in chat.invoke():
                    print(f"# {content.role} - {content.name or '*'}: '{content.content}'")
        finally:
            # Cleanup
            await chat.reset()

if __name__ == "__main__":
    asyncio.run(main())