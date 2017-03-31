###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerfolder_rem_cod_exec.nasl 4849 2016-12-23 10:17:33Z cfi $
#
# PowerFolder Remote Code Execution Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

tag_insight = " Data exchange method between PowerFolder server and clients allows deserialization of untrusted data, which can be exploited to execute arbitrary code.";

tag_impact = "Allows unauthorized disclosure of information; Allows unauthorized modification; Allows disruption of service .";

tag_affected = "PowerFolder 10.4.321 (Linux/Windows) (Other version might be also affected).";

tag_summary = "PowerFolder version 10.4.321 suffers from a remote code execution vulnerability. Proof of concept exploit included.";

tag_solution = "Apply patches that are provided by the vendor. Restrict access to the PowerFolder port, as the vulnerability might be exploited with other gadgets.";

CPE = 'cpe:/a:power:folder';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107010");
  script_version("$Revision: 4849 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-23 11:17:33 +0100 (Fri, 23 Dec 2016) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-06-07 06:40:16 +0200 (Tue, 07 Jun 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("PowerFolder Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://lab.mogwaisecurity.de/advisories/MSA-2016-01/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137172/PowerFolder-10.4.321-Remote-Code-Execution.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_powerfolder_detection.nasl");
  script_mandatory_keys("powerfolder/installed");
  script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if ( !appPort = get_app_port( cpe:CPE)) exit(0);
if ( !appVer = get_app_version( cpe:CPE, port: appPort) ) exit(0);

if ( appVer == "10.4.321" )
{
  security_message( port:appPort);
  exit(0);
}

exit(0); 
