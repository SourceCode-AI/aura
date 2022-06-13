if (window.scan_data == undefined) {
    const data_element = document.getElementById("scan-data");
    window.scan_data = JSON.parse(atob(data_element.textContent));
};

create_components(Vue, AURA_COMPONENTS);


const aura_app = new Vue({
    el: "#app",
    delimiters: ["{(", ")}"],
    data() {
        d = {
            results: window.scan_data
        };

        if (!!window.scan_data) {
            d["selected_scan"] = 0;
        }

        return d;
    }
});
