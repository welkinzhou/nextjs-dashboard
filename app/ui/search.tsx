"use client";

import { MagnifyingGlassIcon } from "@heroicons/react/24/outline";
import { useSearchParams, usePathname, useRouter } from "next/navigation";
import { useDebouncedCallback } from "use-debounce";

export default function Search({ placeholder }: { placeholder: string }) {
  const searchParams = useSearchParams(); // 获取路由查询条件
  const pathname = usePathname(); // 获取路由地址
  const { replace } = useRouter();

  const handleSearch = useDebouncedCallback((term) => {
    // 解析原有查询条件
    const params = new URLSearchParams(searchParams);
    // 查询页数回到首页
    params.set("page", "1");
    // 修改路由 query 参数
    // 只针对 query 如果有别的参数会保留
    if (term) {
      params.set("query", term);
    } else {
      params.delete("query");
    }
    // 拼接路由
    replace(`${pathname}?${params.toString()}`);
  }, 300);

  return (
    <div className="relative flex flex-1 flex-shrink-0">
      <label htmlFor="search" className="sr-only">
        Search
      </label>
      <input
        className="peer block w-full rounded-md border border-gray-200 py-[9px] pl-10 text-sm outline-2 placeholder:text-gray-500"
        placeholder={placeholder}
        onChange={(e) => {
          handleSearch(e.target.value);
        }}
        defaultValue={searchParams.get("query")?.toString()}
      />
      <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-gray-500 peer-focus:text-gray-900" />
    </div>
  );
}
