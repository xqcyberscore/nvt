###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_hostmap_net.nasl 12117 2018-10-26 10:50:36Z cfischer $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Ange Gutek
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104068");
  script_version("$Revision: 12117 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:50:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap NSE net: hostmap");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE net");
  script_dependencies("nmap_nse_net.nasl");
  script_mandatory_keys("Tools/Launch/nmap_nse_net");

  script_add_preference(name:"hostmap.prefix", value:"", type:"entry");
  script_add_preference(name:"http.pipeline", value:"", type:"entry");
  script_add_preference(name:"http.useragent", value:"", type:"entry");
  script_add_preference(name:"http-max-cache-size", value:"", type:"entry");

  script_xref(name:"URL", value:"http://www.bfk.de/bfk_dnslogger.html");

  script_tag(name:"summary", value:"Tries to find hostnames that resolve to the target's IP address by querying the online database at
the linked reference.

The script is in the 'external' category because it sends target IPs to a third party in order to
query their database.

SYNTAX:

hostmap.prefix:  If set, saves the output for each host in a file
called '<prefix><target>'. The file contains one entry per line.

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http.useragent:  The value of the User-Agent header field sent with
requests. By default it is
''Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)''.
A value of the empty string disables sending the User-Agent header field.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.");

  exit(0);
}

include("nmap.inc");

# The corresponding NSE script doesn't belong to the 'safe' category
if (safe_checks()) exit(0);

phase = 0;
if (defined_func("scan_phase")) {
  phase = scan_phase();
}

if (phase == 1) {
    argv = make_array();

    pref = script_get_preference("hostmap.prefix");
    if (!isnull(pref) && pref != "") {
        argv["hostmap.prefix"] = string('"', pref, '"');
    }
    pref = script_get_preference("http.pipeline");
    if (!isnull(pref) && pref != "") {
        argv["http.pipeline"] = string('"', pref, '"');
    }
    pref = script_get_preference("http.useragent");
    if (!isnull(pref) && pref != "") {
        argv["http.useragent"] = string('"', pref, '"');
    }
    pref = script_get_preference("http-max-cache-size");
    if (!isnull(pref) && pref != "") {
        argv["http-max-cache-size"] = string('"', pref, '"');
    }
    nmap_nse_register(script:"hostmap", args:argv);
} else if (phase == 2) {
    res = nmap_nse_get_results(script:"hostmap");
    foreach portspec (keys(res)) {
        output_banner = 'Result found by Nmap Security Scanner (hostmap.nse) http://nmap.org:\n\n';
        if (portspec == "0") {
            log_message(data:output_banner + res[portspec], port:0);
        } else {
            v = split(portspec, sep:"/", keep:0);
            proto = v[0];
            port = v[1];
            log_message(data:output_banner + res[portspec], port:port, protocol:proto);
        }
    }
}
