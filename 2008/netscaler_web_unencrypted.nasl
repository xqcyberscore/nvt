# OpenVAS Vulnerability Test
# $Id: netscaler_web_unencrypted.nasl 4683 2016-12-06 08:45:07Z cfi $
# Description: Unencrypted NetScaler web management interface
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2007 nnposter
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web management interface does not encrypt connections. 

Description :

The remote Citrix NetScaler web management interface does use TLS or
SSL to encrypt connections.";

tag_solution = "Consider disabling this port completely and using only HTTPS.";

if (description)
    {
    script_oid("1.3.6.1.4.1.25623.1.0.80026");
    script_version("$Revision: 4683 $");
    script_tag(name:"last_modification", value:"$Date: 2016-12-06 09:45:07 +0100 (Tue, 06 Dec 2016) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_name("Unencrypted NetScaler web management interface");
    script_family("Web Servers");
    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (c) 2007 nnposter");
    script_dependencies("netscaler_web_detect.nasl");
    script_require_keys("www/netscaler");
    script_require_ports("Services/www",80);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name:"qod_type", value:"general_note");
    exit(0);
    }


if (!get_kb_item("www/netscaler")) exit(0);


include("http_func.inc");


function is_ssl(port)
{
local_var encaps;
encaps = get_port_transport( port );
if ( encaps && encaps>=ENCAPS_SSLv2 && encaps<=ENCAPS_TLSv12 )
	return TRUE;
 else
	return FALSE;
}


port=get_http_port(default:80);
if (!get_tcp_port_state(port) || !get_kb_item("www/netscaler/"+port))
    exit(0);

if (!is_ssl(port:port)) security_message(port);
