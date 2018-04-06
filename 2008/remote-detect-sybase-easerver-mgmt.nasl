# OpenVAS Vulnerability Test
# $Id: remote-detect-sybase-easerver-mgmt.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: This script ensure that the Sybase EAServer management console is running
#
# remote-detect-sybase-easerver-mgmt.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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

tag_summary = "The remote host is running the Sybase Enterprise Application Server JSP Administration Console.  
Sybase EAServer is the open application server from Sybase Inc an enterprise software and services company,
exclusively focused on managing and mobilizing information.

This NVT was deprectated and the detection of the Server Management Console was moved to remote-detect-sybase-easerver.nasl
";

tag_solution = "It's recommended to allow connection to this host only from trusted host or networks,
or disable the service if not used.";



if(description)
{
script_oid("1.3.6.1.4.1.25623.1.0.80005");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9349 $");
script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
script_tag(name:"cvss_base", value:"0.0");
name = "Sybase Enterprise Application Server Management Console detection";
script_name(name);
 

script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"general_note"); 

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_dependencies("find_service.nasl", "remote-detect-sybase-easerver.nasl");
script_require_ports("Services/www");
script_require_keys("SybaseEAServer/installed");
script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);

script_tag(name:"deprecated", value:TRUE);

exit(0);
}

#
# The script code starts here
#

exit(66);

