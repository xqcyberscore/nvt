###############################################################################
# OpenVAS Vulnerability Test
# $Id: modperl_version.nasl 5390 2017-02-21 18:39:27Z mime $
#
# mod_perl version Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Get the Version of mod_perl and store it in KB.";

if (description)
{
 script_id(100129);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("mod_perl version Detection");  

 script_summary("Store version of mod_perl in KB");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("apache/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100129";
SCRIPT_DESC = "mod_perl version Detection";

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item("Services/www/" + port + "/embedded"))exit(0);

if(!banner = get_http_banner(port))exit(0);
if(!egrep(pattern:"Server: .*Apache", string:banner))exit(0);

if(!matches = eregmatch(string:banner, pattern:"mod_perl/([0-9.]+)"))exit(0);

if(!isnull(matches[1])) {
    
  tmp_version = string(matches[1]);
  set_kb_item(name: string("www/", port, "/mod_perl"), value: tmp_version);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:apache:mod_perl:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

exit(0);
