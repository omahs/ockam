use crate::node::{get_node_name, initialize_node_if_default};
use crate::util::is_tty;
use crate::{
    docs,
    util::{api, extract_address_value, node_rpc, Rpc},
    CommandGlobalOpts, OutputFormat,
};
use clap::Args;
use colorful::Colorful;
use miette::IntoDiagnostic;
use ockam_api::nodes::models;
use serde_json::json;

const AFTER_LONG_HELP: &str = include_str!("./static/create/after_long_help.txt");

#[derive(Clone, Debug, Args)]
#[command(after_long_help = docs::after_help(AFTER_LONG_HELP))]
pub struct TcpConnectionNodeOpts {
    /// Node that will initiate the connection
    #[arg(global = true, short, long, value_name = "NODE")]
    pub from: Option<String>,
}

/// Create a TCP connection
#[derive(Args, Clone, Debug)]
#[command(arg_required_else_help = true)]
pub struct CreateCommand {
    #[command(flatten)]
    node_opts: TcpConnectionNodeOpts,

    /// The address to connect to
    #[arg(id = "to", short, long, value_name = "ADDRESS")]
    pub address: String,
}

impl CreateCommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        initialize_node_if_default(&opts, &self.node_opts.from);
        node_rpc(run_impl, (opts, self))
    }

    fn print_output(
        &self,
        opts: &CommandGlobalOpts,
        response: &models::transport::TransportStatus,
    ) -> miette::Result<()> {
        // if output format is json, write json to stdout.
        match opts.global_args.output_format {
            OutputFormat::Plain => {
                if !is_tty(std::io::stdout()) {
                    println!("{}", response.multiaddr().into_diagnostic()?);
                    return Ok(());
                }
                let from = get_node_name(&opts.state, &self.node_opts.from);
                let to = response.socket_addr().into_diagnostic()?;
                if opts.global_args.no_color {
                    println!("\n  TCP Connection:");
                    println!("    From: /node/{from}");
                    println!("    To: {} (/ip4/{}/tcp/{})", to, to.ip(), to.port());
                    println!("    Address: {}", response.multiaddr().into_diagnostic()?);
                } else {
                    println!("\n  TCP Connection:");
                    println!("{}", format!("    From: /node/{from}").light_magenta());
                    println!(
                        "{}",
                        format!("    To: {} (/ip4/{}/tcp/{})", to, to.ip(), to.port())
                            .light_magenta()
                    );
                    println!(
                        "{}",
                        format!("    Address: {}", response.multiaddr().into_diagnostic()?)
                            .light_magenta()
                    );
                }
            }
            OutputFormat::Json => {
                let json = json!([{"route": response.multiaddr().into_diagnostic()? }]);
                println!("{json}");
            }
        }
        Ok(())
    }
}

async fn run_impl(
    ctx: ockam::Context,
    (opts, cmd): (CommandGlobalOpts, CreateCommand),
) -> miette::Result<()> {
    let from = get_node_name(&opts.state, &cmd.node_opts.from);
    let node_name = extract_address_value(&from)?;
    let mut rpc = Rpc::background(&ctx, &opts, &node_name)?;
    let request = api::create_tcp_connection(&cmd);
    rpc.request(request).await?;
    let response = rpc.parse_response::<models::transport::TransportStatus>()?;

    cmd.print_output(&opts, &response)
}
