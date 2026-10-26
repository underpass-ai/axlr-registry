//! `axlr-registry-local`: the registry on the loopback, from memory, so the
//! AXLR console can publish and install tools and skills end to end without
//! AWS. It wires the in-memory adapters to the deployed use cases and the
//! publish API's routing, serves the signed catalog as static files on the
//! same port, runs each version's tests inline (a skill's checks in
//! process, a tool's suite under bubblewrap when it is available), approves
//! what passes as `local-reviewer` unless told not to, and signs every
//! index with a minisign key it keeps in its key directory. One type per
//! file; `main.rs` only parses the flags and calls [`run`].

mod http_bridge;
mod index_key;
mod local_error;
mod local_options;
mod local_registry;
mod local_route;
mod local_server;
mod queued_scheduler;
mod system_clock;

use std::sync::Arc;

pub use http_bridge::HttpBridge;
pub use index_key::IndexKey;
pub use local_error::LocalError;
pub use local_options::LocalOptions;
pub use local_registry::LocalRegistry;
pub use local_route::LocalRoute;
pub use local_server::LocalServer;
pub use queued_scheduler::QueuedScheduler;
use registry_runner::Confinement;
pub use system_clock::SystemClock;

/// Builds the registry the options describe (index key, publisher, an
/// empty signed index) and binds its listener, without serving yet.
pub async fn start(options: &LocalOptions, confinement: Confinement) -> Result<(LocalServer, Arc<LocalRegistry>), LocalError> {
    options.check()?;
    let key = IndexKey::load_or_create(&options.key_dir)?;
    let registry = LocalRegistry::new(&options.catalog, key, confinement, options.auto_approve)?;
    if let Some((id, key, namespaces)) = options.publisher()? {
        registry.register_publisher(id, key, namespaces).await?;
    }
    registry.publish().await?;
    let server = LocalServer::bind(options.listen).await?;
    Ok((server, Arc::new(registry)))
}

/// What the harness prints on start: where it serves and what to put in
/// the console's settings.
pub fn banner(options: &LocalOptions, server: &LocalServer, registry: &LocalRegistry) -> String {
    let base = server.base_url();
    let publisher = match (&options.publisher_id, options.publisher()) {
        (Some(id), Ok(Some((_, key, _)))) => {
            format!("{id} (key id {}, namespaces {})", registry_domain::KeyId::of(&key).as_str(), options.namespaces.join(","))
        }
        _ => "none registered (--publisher-id and --publisher-key)".to_owned(),
    };
    let tests = match registry.confinement() {
        Confinement::Bubblewrap => "skills checked in process; tools run under bubblewrap".to_owned(),
        Confinement::Environment => "skills checked in process; tools run unconfined".to_owned(),
        Confinement::Unavailable(reason) => format!("skills checked in process; {reason}"),
    };
    let review = if registry.auto_approve() {
        format!("automatic, as {}", LocalRegistry::REVIEWER)
    } else {
        format!("manual: POST {base}/local/approve/{{name}}/{{version}}")
    };
    format!(
        "axlr-registry-local serving catalog {catalog} at {base}\n\
         base_url    {base}\n\
         public_key  {public_key}\n\
         index       {base}/index.json (and .minisig)\n\
         publish     {base}/v1/versions\n\
         key file    {key_file}\n\
         publisher   {publisher}\n\
         tests       {tests}\n\
         review      {review}",
        catalog = options.catalog,
        public_key = registry.key().public_key_line(),
        key_file = registry.key().public_path().display(),
    )
}

/// Starts the harness, prints the banner and serves until the process ends.
pub async fn run(options: LocalOptions) -> Result<(), LocalError> {
    let (server, registry) = start(&options, Confinement::detect()).await?;
    println!("{}", banner(&options, &server, &registry));
    server.serve(registry).await
}
