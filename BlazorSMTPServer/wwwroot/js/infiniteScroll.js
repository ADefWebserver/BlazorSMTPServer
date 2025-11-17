(function(){
  const registry = new WeakMap();

  function observe(element, dotNetRef){
    if(!('IntersectionObserver' in window)){
      // Fallback: fire immediately once
      dotNetRef.invokeMethodAsync('OnInfiniteScroll');
      return;
    }

    const options = { root: null, rootMargin: '200px', threshold: 0 };
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries){
        if (entry.isIntersecting){
          // Trigger .NET callback
          dotNetRef.invokeMethodAsync('OnInfiniteScroll');
        }
      }
    }, options);

    observer.observe(element);
    registry.set(element, observer);
  }

  function disconnect(element){
    const observer = registry.get(element);
    if(observer){
      observer.disconnect();
      registry.delete(element);
    }
  }

  window.infiniteScroll = { observe, disconnect };
})();
