use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        privileged_portals_support: { all(target_os = "linux", feature = "privileged_portals") }
    }
}
