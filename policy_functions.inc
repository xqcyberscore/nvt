###############################################################################
# OpenVAS Vulnerability Test support library
# $Id: policy_functions.inc 10714 2018-08-01 14:49:06Z emoss $
#
# Supporting methods for Policy NVTs.
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

function policy_logging(text)
{
  # This function is used by basic policy tests. The silence value is set in
  # compliance_tests.nasl. If you start the test within a standard policy like
  # IT-Grundschutz, the results are silent by default. If you start the basic
  # policy test by themselves, they are verbose.
  local_var verbose, text;
  verbose = get_kb_item("Compliance/verbose");
  if(verbose){
    log_message(data:text, port:0);
  }
}

function policy_add_oid(){
  set_kb_item(name:"PolicyOIDs", value:get_script_oid());
}

function policy_set_compliance(compliant){
  local_var compliant, name;
  name = get_script_oid() + "/COMPLIANT";
  set_kb_item(name:name, value:compliant);
}

function policy_set_kb(val){
  local_var val;
  name = get_script_oid() + "/RESULT";
  # save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:name, value:chomp(string(val)));
}

function policy_set_dval(dval){
  local_var dval;
  name = get_script_oid() + "/DEFAULT";
  # save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:name, value:chomp(string(dval)));
}

function policy_fixtext(fixtext){
  local_var fixtext, name;
  name = get_script_oid() + '/FIX';
  fixtext = str_replace(string:fixtext,find:'\n', replace:' ');
  set_kb_item(name:name, value:fixtext);
}

function policy_control_name(title){
  local_var title, name;
  name = get_script_oid() + '/NAME';
  title = str_replace(string:title,find:'\n', replace:' ');
  set_kb_item(name:name, value:title);
}

function policy_logging_registry(type,key,item,value){
	local_var type,key,item,value;
	policy_logging(text:'Registry value ' + type + '\\' + key + '!' + item + ' is set to: ' + value);
}

function rsop_securitysettingsboolean(select,keyname){
	# rsop only delivers results for domain admins
  local_var select,keyname;

  host = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();
  domain  = kb_smb_domain();
  if( domain ) usrname = domain + "\" + usrname;

  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
    if(!handle){
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    wmi_close(wmi_handle:handle);
    exit(0);
  }

  query = "SELECT " + select + " FROM RSOP_SecuritySettingBoolean WHERE KeyName = '" + keyname + "' AND precedence = '1'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  splitRes = split(res, sep:"|", keep:FALSE);
  if(max_index(splitRes) < 4){
  	return('');
  }
  returnValue = splitRes[4];

  wmi_close(wmi_handle:handle);
  return(string(returnValue));
}

function rsop_securitysettingsnumeric(select,keyname){
	# rsop only delivers results for domain admins
  local_var select,keyname;

  host = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();
  domain  = kb_smb_domain();
  if( domain ) usrname = domain + "\" + usrname;

  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
    if(!handle){
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    wmi_close(wmi_handle:handle);
    exit(0);
  }

  query = "SELECT " + select + " FROM RSOP_SecuritySettingNumeric WHERE KeyName = '" + keyname + "' AND precedence = '1'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  splitRes = split(res, sep:"|", keep:FALSE);
  if(max_index(splitRes) < 4){
  	return('');
  }
  returnValue = splitRes[4];

  wmi_close(wmi_handle:handle);
  return(string(returnValue));
}

function rsop_userprivilegeright(select,keyname){
  # rsop only delivers results for domain admins
  local_var select,keyname;

  host = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();
  domain  = kb_smb_domain();
  if( domain ) usrname = domain + "\" + usrname;

  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
    if(!handle){
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    wmi_close(wmi_handle:handle);
    exit(0);
  }

  query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = '" + keyname + "'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  if(res == ''){
    return "None";
  }

  splitRes = split(res, keep:FALSE);
  accountList = split(splitRes[1], sep:"|", keep:FALSE);
  MaxIndexAccountList = max_index(accountList);
  for(i=0;i<MaxIndexAccountList-2;i++){
    returnValue += accountList[i];
    if(i<MaxIndexAccountList-3){
      returnValue += ', ';
    }
  }

  wmi_close(wmi_handle:handle);
  return(string(returnValue));
}

function win32_useraccount(select,name){
	local_var select,name;

	host = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();
  domain  = kb_smb_domain();
  if( domain ) usrname = domain + "\" + usrname;

  handle = wmi_connect(host:host, username:usrname, password:passwd);
    if(!handle){
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    wmi_close(wmi_handle:handle);
    exit(0);
  }

  query = "SELECT " + select + " FROM Win32_UserAccount WHERE Name = '" + name + "'";
  res = wmi_query(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);

	return(res);
}