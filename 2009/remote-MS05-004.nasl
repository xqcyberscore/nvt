# OpenVAS Vulnerability Test
# $Id: remote-MS05-004.nasl 5016 2017-01-17 09:06:21Z teissa $
# Description: 
# Microsoft Security Bulletin MS05-004
# ASP.NET Path Validation Vulnerability
#
# Affected Software: 
#
# Microsoft .NET Framework 1.0 
# Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4
# Windows XP Service Pack 1 or Windows XP Service Pack 2
# Windows Server 2003, Windows Server 2003 Service Pack 1, or Windows Server 2003 Service Pack 2
# Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2
# Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems, 
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Windows Vista
# Windows XP Tablet PC Edition
# Windows XP Media Center Edition
# Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4
# Windows XP Service Pack 1 or Windows XP Service Pack 2
# Windows Server 2003, Windows Server 2003 Service Pack 1, or Windows Server 2003 Service Pack 2
# Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2
# Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems, 
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Microsoft .NET Framework 1.1 
# Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4
# Windows XP Service Pack 1 or Windows XP Service Pack 2
# Windows XP Tablet PC Edition
# Windows XP Media Center Edition
# Windows XP Professional x64 Edition or Windows XP Professional x64 Edition Service Pack 2
# Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2
# Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems, 
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Windows Vista
# Windows Server 2003
# Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4
# Windows XP Service Pack 1 or Windows XP Service Pack 2
# Windows XP Tablet PC Edition
# Windows XP Media Center Edition
# Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2
# Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems, 
# or Windows Server 2003 with SP2 for Itanium-based Systems  
#
# Non-Affected Software:
# None
#
# Affected Components:
# ASP.NET
#
# remote-MS05-004.nasl
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

include("revisions-lib.inc");
tag_summary = "A canonicalization vulnerability exists in ASP.NET that could allow an attacker to bypass the security of an ASP.NET Web site 
and gain unauthorized access. An attacker who successfully exploited this vulnerability could take a variety of actions, 
depending on the specific contents of the website.";

tag_solution = "Microsoft has released a patch to correct this issue,
you can download it from the following web site:
http://www.microsoft.com/technet/security/Bulletin/MS05-004.mspx";

if(description)
{
script_oid("1.3.6.1.4.1.25623.1.0.101010");
script_version("$Revision: 5016 $");
script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
script_tag(name:"creation_date", value:"2009-03-15 22:16:07 +0100 (Sun, 15 Mar 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_bugtraq_id(11342);
script_cve_id("CVE-2004-0847");
script_name("Microsoft Security Bulletin MS05-004");
 
script_tag(name: "qod_type", value: "remote_banner");
script_tag(name: "solution_type", value: "VendorFix");

script_category(ACT_GATHER_INFO);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
script_family("Windows : Microsoft Bulletins");
script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
script_require_ports("Services/www");
script_mandatory_keys("dotNET/version", "dotNET/port");

script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);

exit(0);

}


#
# The script code starts here
#


dotnet = get_kb_item("dotNET/version"); 
port = get_kb_item("dotNET/port");

if(!dotnet)
	exit(0);

else
{
	# Microsoft .Net Framework version 1.0
	dotnetversion['1.0'] = revcomp(a:dotnet, b:"1.0.3705.6021");
		
	# Microsoft .Net Framework 1.1
	dotnetversion['1.1'] = revcomp(a:dotnet, b:"1.1.4322.2037");

	foreach version (dotnetversion)
	{

	    	if (version == -1){
		    	# Report 'Microsoft ASP.NET Path Validation Vulnerability (MS05-004)'
        		report = 'Missing MS05-004 patch, detected Microsoft .Net Framework version: ' + dotnet;
			security_message(port:port, data:report);
                        exit( 0 );
		}
	}
}

exit( 0 );
