# OpenVAS Vulnerability Test
# $Id: remote-MS07-040.nasl 8022 2017-12-07 08:23:28Z teissa $
# Description: 
# Microsoft Security Bulletin MS07-040 - Critical
# Vulnerabilities in .NET Framework Could Allow Remote Code Execution 
# NET PE Loader Vulnerability - CVE-2007-0041
# ASP.NET Null Byte Termination Vulnerability - CVE-2007-0042
# .NET JIT Compiler Vulnerability - CVE-2007-0043
#
# remote-MS07-040.nasl
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
tag_summary = "Microsoft .NET is affected by multiples criticals vulnerabilities. 
Two of these vulnerabilities could allow remote code execution on client systems with .NET Framework installed, 
and one could allow information disclosure on Web servers running ASP.NET.";

tag_solution = "Microsoft has released an update to correct this issue,
you can download it from the following web site:
http://www.microsoft.com/technet/security/bulletin/ms07-040.mspx";



if(description)
{
script_id(101005);
script_version("$Revision: 8022 $");
script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:23:28 +0100 (Thu, 07 Dec 2017) $");
script_tag(name:"creation_date", value:"2009-03-15 21:09:08 +0100 (Sun, 15 Mar 2009)");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_cve_id("CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043");
name = "Microsoft Security Bulletin MS07-040";
script_name(name);
 
script_tag(name:"qod_type", value:"remote_banner"); 


script_category(ACT_ATTACK);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Windows : Microsoft Bulletins";
script_family(family);
script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
script_mandatory_keys("dotNET/version");

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
	# Microsoft .NET Framework version < [1.0 SP3, 1.1 SP1, 2.0 SP2]
	dotnetversion['1.0'] = revcomp(a:dotnet, b:"1.0.3705.6060"); 
	dotnetversion['1.1'] = revcomp(a:dotnet, b:"1.1.4332.2407"); 
	dotnetversion['2.0'] = revcomp(a:dotnet, b:"2.0.50727.832"); 
		
	foreach version (dotnetversion)
	{

	    	if (version == -1){
		
			# report MS07-04 vulnerability
		    	report  = 'Missing MS07-040 patch, detected Microsoft .Net Framework version: ' + dotnet;
			security_message(port:port, data:report);
		}
	}
}
