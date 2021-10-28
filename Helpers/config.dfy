include "Structs.dfy"

module Config {
  import opened Structs

  // Note - we're assuming that this function is being called
  // only once parse_config has been called in SSA, which would
  // have set up the global_config with str_hashmap_create(20)
  method get_app_config(app_path : string)
    returns (config : ssa_config_t)
  {
    // for now we are using an empty config
    config := new ssa_config_t.Init();
    config.trust_store := app_path;
  }
}