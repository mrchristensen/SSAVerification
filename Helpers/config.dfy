include "Structs.dfy"

module config {
  import opened Structs

  method get_app_config(app_path : string)
  {
    //todo: return config from hashmap if it's there, if not: use the default config
    // return new tls_opts;
    var config : ssa_config_t;
  }
}