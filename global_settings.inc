# OpenVAS Vulnerability Test
# $Id: global_settings.inc 10964 2011-05-18 20:50:52Z jan $
# Description: Methods for handling global settings
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 2004 Anonymous
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
#

global_var	report_verbosity, log_verbosity, debug_level;

report_verbosity = 1;
debug_level = 0;
log_verbosity = 1;
all_addr_private = 0;
all_addr_public = 0;


__gs_opt = get_kb_item("global_settings/network_type");
if (__gs_opt)
{
  if ("LAN" >< __gs_opt) all_addr_private = 1;
  else if ("Internet" >< __gs_opt) all_addr_public = 1;
}




__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}

__gs_opt = get_kb_item("global_settings/log_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) log_verbosity = 1;
  else if ("Quiet" >< __gs_opt) log_verbosity = 0;
  else if ("Verbose" >< __gs_opt) log_verbosity = 2;
  else if ("Debug" >< __gs_opt)
  {
   log_verbosity = 3;
   __gs_opt = get_kb_item("global_settings/debug_level");
   if (__gs_opt =~ '^[0-9]+$') debug_level = int(__gs_opt);
   if (debug_level <= 0) debug_level = 1;
  }
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function log_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level <= 0 || log_verbosity < level) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("LOG: ", msg);
}

GLOBAL_SETTINGS_INC = 1;
