#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use nw_core::service::{Client, Command, Sensitive};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tauri::Manager;
#[derive(Clone)]
struct Proxy {
    client: Arc<tokio::sync::Mutex<Option<Client>>>,
}
impl Proxy {
    fn new() -> Result<Self, String> {
        Ok(Self {
            client: Arc::default(),
        })
    }
    fn binary() -> Result<PathBuf, String> {
        let file = format!("nymwrapd{}", std::env::consts::EXE_SUFFIX);
        let mut candidates = vec![
            std::env::current_exe()
                .map_err(|_| "runtime_component_missing")?
                .parent()
                .ok_or("runtime_component_missing")?
                .join(&file),
        ];
        if cfg!(debug_assertions) {
            candidates.push(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/debug")
                    .join(file),
            );
        }
        candidates
            .into_iter()
            .find(|p| p.is_file())
            .ok_or_else(|| "runtime_component_missing".into())
    }
    async fn ready(&self) -> Result<Client, String> {
        let mut connection = self.client.lock().await;
        if let Some(client) = &*connection {
            match client.request(Command::Status {}).await {
                Ok(_) => return Ok(client.clone()),
                Err(code) if code == "ipc_unavailable" => {}
                Err(code) => return Err(code),
            }
            *connection = None;
        }
        let binary = Self::binary()?;
        let client = Client::spawn_daemon(&binary).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..50 {
                match client.request(Command::Status {}).await {
                    Ok(_) => return Ok(()),
                    Err(code) if code == "ipc_unavailable" || code == "ipc_timeout" => {}
                    Err(code) => return Err(code),
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err("daemon_start_failed".to_owned())
        })
        .await
        .map_err(|_| "daemon_start_failed")??;
        *connection = Some(client.clone());
        Ok(client)
    }
    async fn call(&self, command: Command) -> Result<Value, String> {
        self.ready().await?.request(command).await?.into_json()
    }
    async fn close_request(&self, command: Command) -> Result<nw_core::service::Reply, String> {
        let client = self.client.lock().await.clone().ok_or("workspace_locked")?;
        client.request(command).await
    }
}
macro_rules! command{
    ($name:ident,$variant:ident,{$($field:ident:$ty:ty),*$(,)?})=>{
        #[tauri::command]
        async fn $name($($field:$ty,)* state:tauri::State<'_,Proxy>)->Result<Value,String>{state.call(Command::$variant{$($field,)*}).await}
    };
}
command!(status, Status, {});
command!(workspace_status, WorkspaceStatus, {});
command!(clear_session, Lock, {});
command!(preview_shield,PreviewShield,{input:nw_core::PreviewInput});
command!(load_secrets, LoadSecrets, {});
command!(load_device_probe, LoadDeviceProbe, {});
command!(run_device_probe, RunDeviceProbe, {});
command!(load_provider_keys, LoadProviderKeys, {});
command!(retire_provider_key,RetireProviderKey,{id:String});
#[tauri::command]
async fn add_provider_key(key: String, state: tauri::State<'_, Proxy>) -> Result<Value, String> {
    state
        .call(Command::AddProviderKey {
            key: Sensitive::new(key),
        })
        .await
}
command!(save_secrets,SaveSecrets,{secrets:Vec<nw_core::workspace::SecretRecord>});
command!(load_config, LoadConfig, {});
command!(load_bridge_status, LoadBridgeStatus, {});
command!(save_bridges,SaveBridges,{config:Option<nw_core::service::BridgeConfig>});
command!(load_network_usage, LoadNetworkUsage, {});
command!(start_model, StartModel, {});
command!(save_config,SaveConfig,{config:Box<nw_core::config::Config>});
command!(load_summary, LoadSummary, {});
command!(load_persona, LoadPersona, {});
command!(research_persona, ResearchPersona, {});
command!(confirm_traits,ConfirmTraits,{choices:Vec<(String,bool)>});
command!(generate_plan,GeneratePlan,{input:nw_core::planning::PlanInput,socket:String,secrets:Vec<nw_core::workspace::SecretRecord>});
command!(load_plan, LoadPlan, {});
command!(approve_plan,ApprovePlan,{hash:String});
command!(load_day, LoadDay, {});
command!(generate_day, GenerateDay, {});
command!(approve_day,ApproveDay,{hash:String});
command!(daily_tasks, DailyTasks, {});
command!(complete_task,CompleteTask,{task:nw_proto::DriftTask});
command!(pause,Pause,{paused:bool});
command!(chat,Chat,{conversation:String,messages:Vec<nw_llm::Message>,max_tokens:Option<u32>});
command!(remote_chat,RemoteChat,{conversation:String,messages:Vec<nw_llm::Message>,max_tokens:Option<u32>,min_trust:Option<nw_proto::TrustLevel>});
command!(review_remote,ReviewRemote,{conversation:String,messages:Vec<nw_llm::Message>,max_tokens:Option<u32>});
command!(approve_remote,ApproveRemote,{approval_id:String,hash:String});
command!(cancel_remote,CancelRemote,{approval_id:String});
command!(traffic_status, TrafficStatus, {});
command!(session_timing, SessionTiming, {});
command!(start_remote_job,StartRemoteJob,{approval_id:String,hash:String});
command!(load_remote_job,LoadRemoteJob,{id:String});
command!(load_remote_jobs, LoadRemoteJobs, {});
command!(cancel_remote_job,CancelRemoteJob,{id:String});
command!(load_remote_job_input,LoadRemoteJobInput,{id:String});
command!(list_conversations, ListConversations, {});
command!(load_history,LoadHistory,{conversation:String});
command!(save_snapshot,SaveSnapshot,{kind:nw_mirror::SnapshotKind,items:Vec<String>});
command!(purge_candidates, PurgeCandidates, {});
command!(purge_hash,PurgeHash,{batch:nw_purge::Batch});
command!(approve_purge,ApprovePurge,{batch:nw_purge::Batch,hash:String});
command!(purge_template, PurgeTemplate, {});
command!(purge_guide,PurgeGuide,{service:nw_proto::Service});
command!(load_purge_batches, LoadPurgeBatches, {});
command!(record_purge_result,RecordPurgeResult,{hash:String,outcome:nw_purge::guides::ObservedOutcome,completed_steps:Vec<String>});
command!(account_activity,AccountActivity,{count:u64});
command!(shred_domain,ShredDomain,{domain:nw_vault::Domain,confirmation:String});
command!(destroy_data,DestroyData,{confirmation:String});
#[tauri::command]
async fn open_workspace(
    password: String,
    create: bool,
    profile: nw_proto::Profile,
    state: tauri::State<'_, Proxy>,
) -> Result<Value, String> {
    state
        .call(Command::OpenWorkspace {
            password: Sensitive::new(password),
            create,
            profile,
        })
        .await
}
#[tauri::command]
async fn audit_import(
    content: String,
    format: nw_audit::Format,
    encoding: Option<String>,
    state: tauri::State<'_, Proxy>,
) -> Result<Value, String> {
    state
        .call(Command::AuditImport {
            content: Sensitive::new(content),
            format,
            encoding,
        })
        .await
}
fn main() {
    nw_platform::harden_process().expect("process_hardening_failed");
    tauri::Builder::default()
        .manage(Proxy::new().expect("core_endpoint_unavailable"))
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let app = window.app_handle().clone();
                let proxy = window.state::<Proxy>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    let closed = tokio::time::timeout(
                        Duration::from_secs(5),
                        proxy.close_request(Command::CloseSession {}),
                    )
                    .await;
                    if !matches!(
                        closed,
                        Ok(Ok(nw_core::service::Reply::SessionTiming { .. }))
                    ) {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(5),
                            proxy.close_request(Command::Lock {}),
                        )
                        .await;
                    }
                    app.exit(0);
                });
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            workspace_status,
            open_workspace,
            clear_session,
            preview_shield,
            load_secrets,
            load_device_probe,
            run_device_probe,
            load_provider_keys,
            add_provider_key,
            retire_provider_key,
            save_secrets,
            load_config,
            load_bridge_status,
            save_bridges,
            load_network_usage,
            start_model,
            save_config,
            audit_import,
            load_summary,
            load_persona,
            research_persona,
            confirm_traits,
            generate_plan,
            load_plan,
            approve_plan,
            daily_tasks,
            load_day,
            generate_day,
            approve_day,
            complete_task,
            pause,
            chat,
            remote_chat,
            review_remote,
            approve_remote,
            cancel_remote,
            traffic_status,
            session_timing,
            start_remote_job,
            load_remote_job,
            load_remote_jobs,
            cancel_remote_job,
            load_remote_job_input,
            list_conversations,
            load_history,
            save_snapshot,
            purge_candidates,
            purge_hash,
            approve_purge,
            purge_template,
            purge_guide,
            load_purge_batches,
            record_purge_result,
            account_activity,
            shred_domain,
            destroy_data
        ])
        .run(tauri::generate_context!())
        .expect("nymwrap_app_start_failed");
}
