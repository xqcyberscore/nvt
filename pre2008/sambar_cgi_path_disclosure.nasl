###############################################################################
# OpenVAS Vulnerability Test
# $Id: sambar_cgi_path_disclosure.nasl 5134 2017-01-30 08:20:15Z cfi $
#
# Sambar CGIs path disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
###############################################################################

# References:
# From: <gregory.lebras@security-corporation.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 27 Mar 2003 15:25:40 +0100
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#
# Vulnerables:
# Sambar WebServer v5.3 and below 

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11775");
  script_version("$Revision: 5134 $");
  script_bugtraq_id(7207, 7208);
  script_cve_id("CVE-2003-1284");
  script_tag(name:"last_modification", value:"$Date: 2017-01-30 09:20:15 +0100 (Mon, 30 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sambar CGIs path disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/sambar");

  tag_summary = "environ.pl or testcgi.exe is installed. Those CGIs
  reveal the installation directory and some other information 
  that could help a cracker.

  This NVT has been replaced by NVT 'Sambar default CGI info disclosure' 
  (OID: 1.3.6.1.4.1.25623.1.0.80082).";

  tag_solution = "Remove them.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE); 

  exit(0);
}

exit( 66 );