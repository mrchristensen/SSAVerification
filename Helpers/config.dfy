include "Structs.dfy"

module config {
  import opened Structs

  // TODO - FINISH THIS
  // Note - we're assuming that this function is being called
  // only once parse_config has been called in SSA, which would
  // have set up the global_config with str_hashmap_create(20)
  method get_app_config(app_path : string)
  {
    //todo: return config from hashmap if it's there, if not: use the default config
    // return new tls_opts;
    var config : ssa_config_t;

    // if global config is null, return null

    //else
    // config := str_hashmap_get();

    


  }
}