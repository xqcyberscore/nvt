###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_data_loss_prevention_detect.nasl 9996 2018-05-29 07:18:44Z cfischer $
#
# Trend Micro Data Loss Prevention Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103181");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9996 $");
 script_tag(name:"last_modification", value:"$Date: 2018-05-29 09:18:44 +0200 (Tue, 29 May 2018) $");
 script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("Trend Micro Data Loss Prevention Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : "This host is running Trend Micro Data Loss Prevention, a network and
endpoint-based data loss prevention (DLP) solution.");
 script_xref(name : "URL" , value : "http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8443);

url = string("/dsc/");
buf = http_get_cache(item:url, port:port);
if( buf == NULL )exit(0);

if(egrep(pattern: "<title>Trend Micro Data Loss Prevention Logon", string: buf, icase: TRUE))  {

  install = "/dsc";
  vers = string("unknown");
  set_kb_item(name: string("www/", port, "/trend_micro_data_loss_prevention"), value: string(vers," under ",install));
  log_message(port:port);
}

exit(0);
