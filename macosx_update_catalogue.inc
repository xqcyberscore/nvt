catalog_urls = make_array("10.3",
"https://swscan.apple.com/scanningpoints/scanningpointX.xml",
"10.4",
"https://swscan.apple.com/content/catalogs/index.sucatalog https://swscan.apple.com/content/catalogs/index-1.sucatalog",
"10.5",
"https://swscan.apple.com/content/catalogs/others/index-leopard.merged-1.sucatalog",
"10.6",
"https://swscan.apple.com/content/catalogs/others/index-leopard-snowleopard.merged-1.sucatalog",
"10.7",
"https://swscan.apple.com/content/catalogs/others/index-lion-snowleopard-leopard.merged-1.sucatalog",
"10.8",
"https://swscan.apple.com/content/catalogs/others/index-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-mountainlionseed-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
"10.9",
"https://swscan.apple.com/content/catalogs/others/index-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.9seed-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
"10.10",
"https://swscan.apple.com/content/catalogs/others/index-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.10seed-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.10beta-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
"10.11",
"https://swscan.apple.com/content/catalogs/others/index-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.11seed-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.11beta-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
"10.12",
"https://swscan.apple.com/content/catalogs/others/index-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.12seed-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog https://swscan.apple.com/content/catalogs/others/index-10.12beta-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
"10.14",
"https://swscan.apple.com/content/catalogs/others/index-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog");

function get_osx_update_urls( version ){
	local_var version, ver_ary, url;

	if(isnull(version) || version == "") {
        return "unknown";
    }

	ver_ary = split( version, sep:".", keep:FALSE );
	url = catalog_urls[ver_ary[0] + "." + ver_ary[1]];

	return url;
}

function minimum_version_required( minimum_version, current_version ){
    local_var minimum_version, current_version, minimum_version_array, current_version_array;

    if (!minimum_version) return;
    if (!current_version) return;

    minimum_version_array = split( minimum_version, sep:".", keep:FALSE );
    current_version_array = split( current_version, sep:".", keep:FALSE );

    if (int(current_version_array[0]) < int(minimum_version_array[0]) ) {
        log_message(data:"The minimum major version required is " + minimum_version_array[0] + ". Current version: " + current_version_array[0]);
        exit(0);
    }

    if (int(current_version_array[1]) < int(minimum_version_array[1]) ) {
        log_message(data:"The minimum minor version required is " + minimum_version_array[1] + ". Current version: " + current_version_array[1]);
        exit(0);
    }
}
