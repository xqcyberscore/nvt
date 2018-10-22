##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ocs_inventory_ng_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# OCS Inventory NG Persistent Cross-site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902749");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4024");
  script_bugtraq_id(50011);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 16:35:51 +0530 (Tue, 15 Nov 2011)");
  script_name("OCS Inventory NG Persistent Cross-site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46311");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70406");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18005/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"insight", value:"The flaw exists due to certain system information passed via a 'POST' request
  to '/ocsinventory' is not properly sanitised before being used.");
  script_tag(name:"solution", value:"Upgrade to OCS Inventory NG version 2.0.2 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running OCS Inventory NG and is prone to cross site
  scripting vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in
  context of an affected site when the malicious data is being viewed.");
  script_tag(name:"affected", value:"OCS Inventory NG version 2.0.1 and prior");
  script_xref(name:"URL", value:"http://www.ocsinventory-ng.org/fr/");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

ocsPort = get_http_port(default:80);
if(!get_port_state(ocsPort)){
  exit(0);
}

if(!ocsVer = get_version_from_kb(port:ocsPort,app:"OCS_Inventory_NG")){
  exit(0);
}

if(version_is_less(version:ocsVer, test_version:"2.0.2")){
  security_message(ocsPort);
}
