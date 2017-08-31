###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shoreware_director_63019.nasl 6755 2017-07-18 12:55:56Z cfischer $
#
# ShoreTel ShoreWare Director Remote Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103814";
CPE = "cpe:/a:shoretel:shoreware_director";

tag_insight = "By default, the /ShorewareDirector directory is available via
anonymous FTP, unrestricted, and with read-write access.  It is
vulnerable to:

- A Denial of Service (DoS) filling up the disk with arbitrary files.
If the directory resides on the C: drive, it could make the entire
server unavailable.  Otherwise, it could prevent administrators from
changing menu prompts or other system functions utilizing the same
disk.

- Unauthenticated changes and deletion of menu prompts actively being
used by the system.  Deleting an actively used file will cause the
system to use the default greeting.  An attacker could overwrite an
active prompt (can take hours to refresh from the FTP server though)
that would result in a good laugh and high fives, but also could be
used to convince users to take further action or disclose sensitive
information as a step in a more complex attack.";

tag_impact = "Attackers can exploit this issue to bypass security restrictions to
perform unauthorized actions or cause a denial-of-service condition.";

tag_affected = "ShoreWare Director 18.61.7500.0 is vulnerable; other versions may also
be affected.";

tag_summary = "ShoreWare Director is prone to a remote security-bypass vulnerability.";
tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Check the Build version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(63019);
 script_version ("$Revision: 6755 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("ShoreTel ShoreWare Director Remote Security Bypass Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63019");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-18 14:55:56 +0200 (Tue, 18 Jul 2017) $");
 script_tag(name:"creation_date", value:"2013-10-16 12:02:38 +0200 (Wed, 16 Oct 2013)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_shoreware_director_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("ShoreWare_Director/installed");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
build = get_kb_item('www/' + port + '/ShoreWare_Director/build');
if(!build)exit(0);

if(version_is_less(version: build, test_version: "18.61.7500.0")) {
    security_message(port:port);
    exit(0);
}

exit(0);
