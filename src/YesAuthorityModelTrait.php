<?php

namespace LivelyWorks\YesAuthority;
/*
 * Model Trait for YesAuthority
 *-------------------------------------------------------- */

trait YesAuthorityModelTrait
{
    /**
     * Get the permitted items
     * Please note:: this method uses JSON Functions which is available in  MySQL 5.7.8 & above
     *
     * @param string $query       - existing query
     * @param string $permission  - permission to check
     * @param string $table       - table name
     * @param string $column  - permission to check
     *
     * @return query
     *
     * @since  11 JUN 2018
     *------------------------------------------------------------------------ */
    public function scopeIfHasAccess($query, string $permission, string $table = '', string $column = '')
    {
        $tableName = '';
        
        if($table) {
            if(!$column) {
                throw new Exception('userColumn is required for table');
            }

            if(is_numeric($table) or is_numeric($column)) {
                throw new Exception('Argument must be of the type string');
            }

           $query->join(
                $table, $this->table.'.'.$this->primaryKey, 
                '=', 
                $table.'.'.$column
            );

           $tableName = $table . '.';
        }

        $query->whereRaw(
            'JSON_CONTAINS('.$tableName.'__permissions->"$.allow", \'["'.$permission.'"]\') AND !JSON_CONTAINS('.$tableName.'__permissions->"$.deny", \'["'.$permission.'"]\')'
        );

        return $query;
    }
}