export const hydrateState = (state = {}) => ({
  element: el => {
    el.setInnerContent(JSON.stringify(state))
  },
})
