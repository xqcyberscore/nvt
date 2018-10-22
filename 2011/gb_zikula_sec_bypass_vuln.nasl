##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_sec_bypass_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Zikula Security bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801744");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-4728");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Zikula Security bypass Vulnerability");
  script_xref(name:"URL", value:"http://code.zikula.org/core/ticket/2009");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"insight", value:"The flaw exists due to errors in 'rand' and 'srand' PHP functions for random
  number generation");
  script_tag(name:"solution", value:"Upgrade to the Zikula version 1.3.1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Zikula and is prone to security bypass
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to defeat protection
  mechanisms based on randomization by predicting a return value.");
  script_tag(name:"affected", value:"Zikula version prior to 1.3.1");
  script_xref(name:"URL", value:"http://zikula.org/");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

zkPort = get_http_port(default:80);
if(!get_port_state(zkPort)){
  exit(0);
}

if(!zkVer = get_version_from_kb(port:zkPort,app:"zikula")){
  exit(0);
}

if(version_is_less(version:zkVer, test_version:"1.3.1")){
  security_message(port:zkPort);
}
