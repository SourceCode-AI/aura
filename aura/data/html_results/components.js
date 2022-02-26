function intersect(array1, array2){
    return array1.filter(value => array2.includes(value));
}

function hide_elem (cond) {
    if (!cond) {
        return {"d-none": true, "d-print-block": true};
    }
    return {};
}


Vue.component("tree-view", {
    props: {
        name: {required: true},
        data: {required: true, default: {}},
        depth: {default: 0},
        max_depth: {default: 2},
        collapsed: {default: false}
    },
    computed: {
        icon: function() {
            if (this.data.mime == "text/x-python") {
                return "fab fa-python";
            } else if (this.data.mime == "application/gzip") {
                return "fa fa-file-archive";
            } else if (this.data.mime == "text/plain") {
                return "fa fa-file-word";
            } else if (this.data.mime || this.data.size || !this.hasChildren) {
                return "fa fa-file-alt";
            }
            return "fa fa-folder";
        },
        size: function() {
            const sizes = ["b", "Kb", "Mb", "Gb", "Tb"];
            var converted = this.data.size || 0;
            for (var i=0; i<sizes.length; i++) {
                if (converted < 1024) {
                    return converted.toPrecision(4) + " " + sizes[i];
                }
                converted = converted / 1024;
            }
        },
        hasChildren: function(){
            'use strict';
            return this.data && Object.keys(this.data.children).length > 0;
        }
    },
    data: function(){
        'use strict';
        return {collapse: this.collapsed || (this.max_depth<=this.depth)};
    },
    methods: {
        toggle: function(){
            'use strict';
            this.collapse=!this.collapse;
        }
    },
    template: `
    <div>
        <div class="tree-info">
            <span v-if="hasChildren" style="cursor: pointer;" v-on:click="toggle()">
              <i class="fa fa-xs" :class="collapse?'fa-plus-square':'fa-minus-square'"></i>
            </span>
        
            <span class="fa-lg" :class="icon"></span>
            <span class="badge bg-primary" v-if="data.score">Score: {{ data.score }}</span>
            {{ name }}
            <span class="text-muted">
                <span v-if="data.mime">{{ data.mime }}</span>
                <span v-if="data.size">{{ size }}</span>
            </span>
            <br />
            <span class="badge bg-secondary me-1" v-for="tag in data.tags">{{ tag }}</span>
        </div>
        <ul class="tree-view border border-end-0 border-bottom-0" v-if="hasChildren && !collapse">
            <li v-for="(ch_value, ch_name) in data.children">
                <tree-view :name="ch_name" :data="ch_value" :depth="(depth || 0)+1"></tree-view>
            </li>
        </ul>
    </div>
    `
})


Vue.component("behavioral-analysis", {
    props: ["data"],
    methods: {
        get_icon: function(details) {
            if (details.id == "network_access") {
                return "fa fa-network-wired";
            } else if (details.id == "system_execution") {
                return "fa fa-terminal";
            } else if (details.id == "code_execution") {
                return "fab fa-python";
            } else if (details.id == "file_access") {
                return "fa fa-file-export";
            } else if (details.id == "windows") {
                return "fab fa-windows";
            } else if (details.id == "obfuscation") {
                return "fa fa-user-ninja";
            } else if (details.id == "low_level_access") {
                return "fa fa-microchip";
            } else if (details.id == "vulnerability") {
                return "fa fa-bug";
            } else if (details.id == "possible_malware") {
                return "fa fa-virus";
            } else if (details.id == "macos") {
                return "fab fa-apple"
            }
            return "fa fa-fingerprint";
        }
    },
    template: `
    <div class="card shadow">
        <div class="card card-header">
            Behavioral analysis
        </div>
        <ul class="list-group">
            <li class="list-group-item" v-for="(details, pk) in data">
                <h5 class="text-primary"><span :class="get_icon(details)"></span> {{ details.name }}</h5>
                {{ details.description }}
            </li>
        </ul>
    </div>
    `
})

Vue.component("overview", {
    props: ["results"],
    computed: {
        severities: function() {
            var s = {};

            this.results.detections.forEach(function (e) {
                s[e.severity] = (s[e.severity] || 0) + 1;
            });

            return s;
        },
        licenses: function() {
            var all_licenses = [];

            this.results.detections.forEach(function(e) {
                if (!e.tags) return;

                if (e.tags.indexOf("sbom:component") >= 0 && !!e.extra.licenses){
                    e.extra.licenses.forEach(function(l) {
                        if (all_licenses.indexOf(l.license.id) < 0) {
                            all_licenses.push(l.license.id);
                        }
                    });
                }
            });

            return all_licenses;
        },
        start_time: function() {
            return new Date(this.results.metadata.start_time * 1000).toISOString();
        },
        end_time: function() {
            return new Date(this.results.metadata.end_time * 1000).toISOString();
        }
    },
    template: `
    <div>
    <div class="row mt-5">
        <div class="col-lg-6">
            <div class="card shadow">
                <div class="card-header">Overview</div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item d-flex justify-content-between">
                        <b>Input:</b> <code class="code-border">{{ results.metadata.name }}</code>
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <b>Total score:</b> {{ results.score || 0 }}
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <b>SBoM licenses:</b>
                        <div>
                            <span class="badge bg-secondary me-1" v-for="license in licenses">{{ license }}</span>
                        </div>
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <b>Aura version:</b> {{ results.version }}
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <b>Start time:</b> {{ start_time }}
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <b>End time:</b> {{ end_time }}
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <b>Total run time:</b> {{ results.metadata.end_time - results.metadata.start_time }} s
                    </li>
                    
                </ul>
            </div>
        </div>
        <div class="col-lg-6">
            <div class="card shadow">
                <div class="card-header">Detection Severities</div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item list-group-item-dark d-flex justify-content-between">
                        Critical severity
                        <span class="badge bg-dark">{{ severities.critical || 0 }}</span>
                    </li>
                    <li class="list-group-item list-group-item-danger d-flex justify-content-between">
                        High severity
                        <span class="badge bg-danger">{{ severities.high || 0 }}</span>
                    </li>
                    <li class="list-group-item list-group-item-warning d-flex justify-content-between">
                        Medium severity
                        <span class="badge bg-warning">{{ severities.medium || 0 }}</span>
                    </li>
                    <li class="list-group-item list-group-item-primary d-flex justify-content-between">
                        Low severity
                        <span class="badge bg-primary">{{ severities.low || 0 }}</span>
                    </li>
                    <li class="list-group-item list-group-item-secondary d-flex justify-content-between">
                        Unknown severity
                        <span class="badge bg-secondary">{{ severities.unknown || 0 }}</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>
    <div class="row mt-3">
        <div class="col-lg-6">
            <behavioral-analysis :data="results.metadata.behavioral_analysis"></behavioral-analysis>
        </div>
        <div class="col-lg-6">
            <div class="card shadow">
                <div class="card-header">
                    Input data
                </div>
                <div class="card-body">
                    <ul class="tree-view">
                        <li v-for="(value, name) in results.metadata.directory_tree_stats.children">
                            <tree-view :name="name" :data="value"></tree-view>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    </div>
    `
});

Vue.component("sbom", {
    props: {
        component: {}
    },
    template: `
    <div class="col-md-4" style="padding-bottom: 10px">
        <div class="card shadow">
            <h5 class="card-header">
                {{ component.extra.type }} {{ component.extra.name }}  {{ component.extra.version }}
            </h5>
            <ul class="list-group list-group-flush">
                <li class="list-group-item">
                    <b>Type:</b> {{ component.extra.type }}
                </li>
                <li class="list-group-item">
                    <b>Name:</b> {{ component.extra.name }}
                </li>
                <li class="list-group-item">
                    <b>Version:</b> {{ component.extra.version }}
                </li>
                <li class="list-group-item">
                    <b>PURL:</b> {{ component.extra.purl }}
                </li>
                <li class="list-group-item">
                    <b>Author:</b> {{ component.extra.author || "N/A" }}
                </li>
                <li class="list-group-item">
                    <b>Publisher:</b> {{ component.extra.publisher || "N/A" }}
                </li>
                <li class="list-group-item">
                    <b>Licenses:</b>
                    <span class="badge bg-secondary" v-for="license in component.extra.licenses">{{ license.license.id }}</span>
                </li>
            </ul>
            <div class="card-footer" v-if="component.location">
                Found in <code>{{ component.location }}</code>
            </div>
        </div>
    </div>
    `
})

Vue.component("sbom-overview", {
    props: {
        "results": {}
    },
    computed: {
        components: function() {
            var c = []
            for (var i=0; i<this.results.detections.length; i++) {
                var d = this.results.detections[i]

                if (!!d.tags && d.tags.indexOf("sbom:component") >= 0) {
                    c.push(d);
                }
            }

            return c;
        }
    },
    template: `
    <div class="row">
        <div class="col-sm-12 text-center"><h2>Software Bill of Materials</h2></div>
        <div class="alert alert-primary text-center" v-if="components.length==0">
            <h2>
                <span class="fa fa-info-circle"></span>
                No SBoM components have been detected in this scan
            </h2>
        </div>
        <sbom v-for="component in components" :component="component"></sbom>
    </div>
    `
});

Vue.component("detection", {
    props: ["detection"],
    computed: {
        severity: function() {
            if (this.detection.severity == "critical") {
                return "dark"
            } else if (this.detection.severity == "high") {
                return "danger";
            } else if (this.detection.severity == "medium") {
                return "warning";
            } else if (this.detection.severity == "low") {
                return "primary";
            } else {
                return "secondary";
            }
        }
    },
    template: `
    <div class="card shadow">
        <h5 class="card-header d-flex justify-content-between">
            {{ detection.type }}
            <span class="badge" :class="'bg-' + severity" >{{ detection.severity }} severity / Score: {{ detection.score || 0 }}</span>
        </h5>
        <div class="card-body">
            <figure>
                <blockquote class="blockquote">
                    <p>{{ detection.message }}</p>
                </blockquote>
                <figcaption class="blockquote-footer">
                    In {{ detection.location || "Unknown location" }} at line {{ detection.line_no || "N/A" }}
                </figcaption>
            </figure>
            <p class="text-monospace">
                <code class="d-flex code-border">{{ detection.line }}</code>
            </p>
            <p v-if="detection.extra">
                <em>Extra data:</em> <br />
                <small><code><pre>{{ detection.extra }}</pre></code></small>
            </p>
        </div>
        <div class="card-footer">
            <div class="row">
                <div class="col-md-12">
                    Tags:
                    <span class="badge bg-secondary" v-for="tag in detection.tags" style="margin-right:5px">
                        {{ tag }}
                    </span>
                </div>
            </div>
            <slot name="footer"></slot>
        </div>
    </div>
    `
});

Vue.component("toggle-filter", {
    props: {
        "base_color": {
            "default": "btn-outline-primary"
        },
        "target_object": {},
        "target_property": {}
    },
    computed: {
        styles: function() {
            var s = {};
            s[this.base_color] = true;
            return s;
        },
        is_shown: function() {
            var s = Object.assign({}, this.styles);
            if (this.target_object[this.target_property] === true) {
                s.active = true;
            }
            return s;
        },
        is_hidden: function() {
            var s = Object.assign({}, this.styles);
            if (this.target_object[this.target_property] === false) {
                s.active = true;
            }
            return s;
        },
        is_default: function() {
            var s = Object.assign({}, this.styles);
            if (this.target_object[this.target_property] === undefined) {
                s.active = true;
            }
            return s;
        }
    },
    methods: {
        showFilter: function(){
            this.$set(this.target_object, this.target_property, true);
        },
        hideFilter: function(){
            this.$set(this.target_object, this.target_property, false);
        },
        resetFilter: function(){
            this.$delete(this.target_object, this.target_property);
        }
    },
    template: `
    <div class="btn-group btn-group-sm">
        <button type="button" class="btn" :class="is_shown" @click="showFilter()">
            <i class="fas fa-filter"></i>
        </button>
        <button type="button" class="btn" :class="is_hidden" @click="hideFilter()">
            <i class="fas fa-eye-slash"></i>
        </button>
        <button type="button" class="btn" :class="is_default" @click="resetFilter()">
            <i class="fas fa-asterisk"></i>
        </button>
    </div>
    `
})

Vue.component("detection-browser", {
    props: {
        "results": {},
        "tag_filters": {
            "default": function(){
                return {
                    "misc:test_code": false,
                    "sbom:component": false
                };
            }
        },
        "severity_filter": {
            "default": function(){
                return { "unknown": false };
            }
        },
        "text_filter": {
            "default": ""
        }
    },
    computed: {
        detections: function() {
            outer = this;

            var exclude_tags = [];
            var include_tags = [];

            var only_selected_severities = false;

            for (sev_name in this.severity_filter) {
                if (this.severity_filter[sev_name] === true) {
                    only_selected_severities = true;
                    break;
                }
            }

            for (const tag_name in this.tag_filters) {
                if (this.tag_filters[tag_name]) {
                    include_tags.push(tag_name);
                } else {
                    exclude_tags.push(tag_name);
                }
            }

            var filtered = this.results.detections.filter(function(e) {

                if (include_tags.length > 0 && intersect((e.tags || []), include_tags).length != include_tags.length){ return false; }

                if (intersect((e.tags || []), exclude_tags).length > 0){ return false; }

                if (!!outer.text_filter) {
                    const tf = outer.text_filter.toLowerCase()
                    if (!(
                        (e.line && e.line.toLowerCase().includes(tf)) ||
                        (e.message && e.message.toLowerCase().includes(tf))
                    )) { return false; }
                }

                if (outer.severity_filter[e.severity] === false) {
                    return false;
                } else if (only_selected_severities && outer.severity_filter[e.severity] !== true) {
                    return false;
                }

                return true;
            });

            filtered.sort((a, b) => b.score - a.score);

            return filtered;
        },
        severities: function () {
            var s = {};
            this.results.detections.forEach(function(e) {
                s[e.severity] = (s[e.severity] || 0) + 1;
            });
            return s;
        }
    },
    template: `
    <div class="row">
        <div class="col-xl-4 col-md-6 d-print-none">
            <div class="card shadow">
                <h5 class="card-header">
                    Filtering
                </h5>
                <div class="card-body">
                    <div class="row">
                        <input type="text" class="form-control" placeholder="Type to filter" v-model="text_filter">
                    </div>
                    
                    <div class="row mt-2">
                        <div class="card col-sm-12 p-0">
                            <div class="card-header">
                                Filter by severity
                            </div>
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item list-group-item-dark d-flex justify-content-between">
                                    Critical severity
                                    <toggle-filter :base_color="'btn-outline-dark'" :target_object="severity_filter" :target_property="'critical'"></toggle-filter>
                                </li>
                                <li class="list-group-item list-group-item-danger d-flex justify-content-between">
                                    High severity
                                    <toggle-filter :base_color="'btn-outline-danger'" :target_object="severity_filter" :target_property="'high'"></toggle-filter>
                                </li>
                                <li class="list-group-item list-group-item-warning d-flex justify-content-between">
                                    Medium severity
                                    <toggle-filter :base_color="'btn-outline-warning'" :target_object="severity_filter" :target_property="'medium'"></toggle-filter>
                                </li>
                                <li class="list-group-item list-group-item-primary d-flex justify-content-between">
                                    Low severity
                                    <toggle-filter :base_color="'btn-outline-primary'" :target_object="severity_filter" :target_property="'low'"></toggle-filter>
                                </li>
                                <li class="list-group-item list-group-item-secondary d-flex justify-content-between">
                                    Unknown severity
                                    <toggle-filter :base_color="'btn-outline-secondary'" :target_object="severity_filter" :target_property="'unknown'"></toggle-filter>
                                </li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="row mt-2">
                        <div class="card col-lg-12 p-0">
                            <div class="card-header">
                                Filter by tags
                            </div>
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item d-flex justify-content-between align-items-center" v-for="tag in results.tags">
                                    {{ tag }}
                                    <toggle-filter :target_object="tag_filters" :target_property="tag"></toggle-filter>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-8 col-md-6">
            <h2 class="d-none d-print-block">Detections</h2>
            <div class="row">
                <div class="col-sm-12" v-if="detections.length==0">
                    <div class="alert alert-primary text-center">
                        No results to show, try adjusting your filters
                    </div>
                </div>
            
                <div class="col-lg-12 p-3" v-for="detection in detections">
                    <detection :detection="detection" :key="detection.signature"></detection>
                </div>
            </div>
        </div>
    </div>
    `
})

Vue.component("tabs", {
    props: {
        results: {},
        tab: {
            default: "overview"
        },
    },
    methods: {
        "hide_elem": hide_elem
    },
    template: `
    <div>
        <div class="row p-2">
            <h2 class="text-center">Scan results for <mark>{{ results.name }}</mark></h2>
        </div>
    
        <ul class="nav nav-tabs nav-justified d-print-none mt-2">
            <li class="nav-item">
                <a class="nav-link" :class="{active: (tab == 'overview')}" href="#" @click="tab='overview'">Overview</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" :class="{active: (tab == 'detections')}" href="#" @click="tab='detections'">
                <span class="badge bg-secondary">{{ results.detections.length }}</span>
                Detections
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" :class="{active: (tab == 'sbom')}" href="#" @click="tab='sbom'">SBoM</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" :class="{active: (tab == 'raw')}" href="#" @click="tab='raw'">RAW Data</a>
            </li>
        </ul>
        <div class="card">
            <div class="card-body">
                <div :class="hide_elem(tab == 'overview')">
                    <overview :results="results"></overview>
                </div>
                
                <div :class="hide_elem(tab == 'sbom')">
                    <sbom-overview :results="results"></sbom-overview>
                </div>
                
                <div :class="hide_elem(tab == 'detections')">
                    <detection-browser :results="results"></detection-browser>
                </div>
                
                <div v-if="tab == 'raw'">
                    <code><pre>{{ results }}</pre></code>
                </div>
            </div>
        </div>
    </div>
    `
});

