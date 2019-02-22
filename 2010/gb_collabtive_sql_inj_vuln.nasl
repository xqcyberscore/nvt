##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabtive_sql_inj_vuln.nasl 13812 2019-02-21 12:04:05Z jschulte $
#
# Collabtive 'managechat.php' SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801548");
  script_version("$Revision: 13812 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 13:04:05 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-4269");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Collabtive 'managechat.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62930");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15381/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_collabtive_detect.nasl");
  script_mandatory_keys("collabtive/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"insight", value:"The flaws are due to an improper validation of authentication
cookies in the 'managechat.php' script when processing the value of parameter
'actions'.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Collabtive and is prone SQL injection
vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security
restrictions and gain unauthorized administrative access to the vulnerable
application.");
  script_tag(name:"affected", value:"Collabtive version 0.6.5");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

if(!version = get_version_from_kb(port:port, app:"collabtive")){
  exit(0);
}

if(version_is_equal(version:version, test_version:"0.6.5")){
  security_message(port);
}
