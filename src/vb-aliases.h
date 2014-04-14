#ifndef VB_ALIASES_H
#define VB_ALIASES_H

/** Aliases for libvbucket */
#define VB_REMAP(config, vbucket, wrongserver) \
    vbucket_found_incorrect_master(config, vbucket, wrongserver)

#define VB_NODESTR(config, index) \
    vbucket_config_get_server(config, index)

#define VB_VIEWSURL(config, index) \
    vbucket_config_get_couch_api_base(config, index)

#define VB_RESTURL(config, index) \
    vbucket_config_get_rest_api_server(config, index)

#define VB_DISTTYPE(config) vbucket_config_get_distribution_type(config)
#define VB_NREPLICAS(config) vbucket_config_get_num_replicas(config)
#define VB_NSERVERS(config) vbucket_config_get_num_servers(config)
#endif
